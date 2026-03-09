# -*- coding: utf-8 -*-
"""
pygocryptfs.gocryptfs
~~~~~~~~~~~~~~~~~~~~~
Core implementation of the gocryptfs filesystem vault.
Supports AES-GCM, AES-SIV, XChaCha20-Poly1305, EME name encryption,
plain names, Raw64, LongNames, per-directory IVs.

MIT License – Copyright (c) 2024-26 maxpat78
"""

import base64
import hashlib
import io
import json
import locale
import operator
import os
import sys
import struct
import time
import zipfile

try:
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.Cipher import AES, ChaCha20_Poly1305
    from Cryptodome.Hash import SHA256
    from Cryptodome.Random import get_random_bytes
except ImportError:
    from Crypto.Protocol.KDF import HKDF
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    from Crypto.Hash import SHA256
    from Crypto.Random import get_random_bytes

# HKDF context strings (matching gocryptfs source)
S_AES_GCM  = b"AES-GCM file content encryption"
S_AES_SIV  = b"AES-SIV file content encryption"
S_AES_EME  = b"EME filename encryption"
S_XCHACHA  = b"XChaCha20-Poly1305 file content encryption"

BLOCK_SIZE      = 4096          # plaintext block size
BLOCK_OVERHEAD  = 32            # GCM/SIV overhead (nonce+tag)
XCHACHA_EXTRA   = 8             # XChaCha has 24-byte nonce vs 16
ZEROED_PLAIN    = bytes(BLOCK_SIZE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _d64(s, safe=False):
    """Decode base64 (standard or URL-safe), tolerating missing padding."""
    pad = b'===' if isinstance(s, bytes) else '==='
    fn  = base64.urlsafe_b64decode if safe else base64.b64decode
    return fn(s + pad)


def _pad16(s):
    """PKCS#7-style padding to the next 16-byte boundary (minimum 1 byte added)."""
    blen  = len(s)
    # always add at least one padding byte; if already a multiple of 16, add 16
    added = 16 - (blen % 16)
    total = blen + added
    result = bytearray(total)
    result[:blen] = s
    for i in range(blen, total):
        result[i] = added
    return bytes(result)


def _unpad16(s):
    """Remove PKCS#7 padding (last byte tells how many padding bytes were added)."""
    if not s:
        return b''
    pad = s[-1]
    if pad == 0 or pad > 16:
        return bytes(s)   # invalid padding, return as-is
    return bytes(s[:-pad])


def _fmt_size(size):
    """Human-readable file size with locale grouping."""
    suffixes = {0: 'B', 10: 'K', 20: 'M', 30: 'G', 40: 'T', 50: 'E'}
    if size >= 10 ** 12:
        k = 0
        for k in sorted(suffixes):
            if (size // (1 << k)) < 10 ** 6:
                break
        return locale.format_string('%.02f%s', (size / (1 << k), suffixes[k]), grouping=True)
    return locale.format_string('%d', size, grouping=True)


def _real_plaintext_size(encrypted_size, xchacha=False):
    """Calculate the plaintext byte count from the encrypted file size."""
    if not encrypted_size:
        return 0
    overhead = BLOCK_OVERHEAD + (XCHACHA_EXTRA if xchacha else 0)
    cb = (encrypted_size - 18 + (BLOCK_SIZE + overhead - 1)) // (BLOCK_SIZE + overhead)
    return encrypted_size - 18 - cb * overhead


# ---------------------------------------------------------------------------
# AES-256 EME (Encrypt-Mix-Encrypt, Halevi-Rogaway 2003)
# ---------------------------------------------------------------------------

class _AES256_EME:
    """AES-256 EME mode for wide-block filename encryption."""

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 EME requires a 32-byte key")
        self.key = key

    # low-level ECB helpers
    def _ecb(self, data, encrypt=True):
        ciph = AES.new(self.key, AES.MODE_ECB)
        return ciph.encrypt(data) if encrypt else ciph.decrypt(data)

    def encrypt_iv(self, iv, data):
        return self._transform(iv, data, encrypt=True)

    def decrypt_iv(self, iv, data):
        return self._transform(iv, data, encrypt=False)

    def _tabulate_L(self, m):
        Li = self._ecb(bytes(16))
        table = []
        for _ in range(m):
            Li = self._mult2(Li)
            table.append(Li)
        return table

    @staticmethod
    def _xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def _mult2(s):
        s = bytearray(s)
        res = bytearray(16)
        res[0] = (s[0] * 2) & 0xFF
        if s[15] >= 128:
            res[0] ^= 135
        for j in range(1, 16):
            res[j] = (s[j] * 2) & 0xFF
            if s[j - 1] >= 128:
                res[j] += 1
        return bytes(res)

    def _transform(self, tweak, data, encrypt=True):
        if len(tweak) != 16:
            raise ValueError("EME tweak must be 16 bytes")
        if len(data) % 16:
            raise ValueError("EME data must be a multiple of 16 bytes")
        m = len(data) // 16
        if not 1 <= m <= 128:
            raise ValueError("EME data must be 1–128 blocks")

        ecb = self._ecb
        L   = self._tabulate_L(m)
        xor = self._xor

        # Step 1: PPPj = ECB(Pj XOR Lj)
        C = bytearray(len(data))
        for j in range(m):
            Pj  = data[j * 16: j * 16 + 16]
            PPj = xor(Pj, L[j])
            C[j * 16: j * 16 + 16] = ecb(PPj, encrypt)

        # Step 2: MP = XOR-chain of C blocks with tweak
        MP = xor(C[:16], tweak)
        for j in range(1, m):
            MP = xor(MP, C[j * 16: j * 16 + 16])

        MC = ecb(MP, encrypt)
        M  = xor(MP, MC)

        # Step 3: update C[1..m-1] with rotating M
        for j in range(1, m):
            M  = self._mult2(M)
            Cj = C[j * 16: j * 16 + 16]
            C[j * 16: j * 16 + 16] = xor(Cj, M)

        # Step 4: compute CCC[0]
        CCC1 = xor(MC, tweak)
        for j in range(1, m):
            CCC1 = xor(CCC1, C[j * 16: j * 16 + 16])
        C[:16] = CCC1

        # Step 5: final ECB + XOR with L
        for j in range(m):
            Cj = C[j * 16: j * 16 + 16]
            C[j * 16: j * 16 + 16] = xor(ecb(Cj, encrypt), L[j])

        return bytes(C)


# ---------------------------------------------------------------------------
# FileInfo – lightweight stat wrapper
# ---------------------------------------------------------------------------

class FileInfo:
    """Information about a virtual path inside the vault."""

    def __init__(self, virtual_path, real_path, exists, is_dir, stat=None, is_symlink=False):
        self.virtualPath  = virtual_path
        self.realPathName = real_path
        self.exists       = exists
        self.isDir        = is_dir
        self.isSymlink    = is_symlink
        self._stat        = stat

    @property
    def size(self):
        return self._stat.st_size if self._stat else 0

    @property
    def mtime(self):
        return self._stat.st_mtime if self._stat else 0

    @property
    def atime(self):
        return self._stat.st_atime if self._stat else 0


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class Vault:
    """
    High-level interface to a gocryptfs encrypted filesystem.

    Parameters
    ----------
    directory : str
        Path to the root of the gocryptfs vault on the real filesystem.
    password : str, optional
        Password used to decrypt the master key from ``gocryptfs.conf``.
    pk : bytes, optional
        Raw 32-byte master key (skip password-based unlocking).
    """

    def __init__(self, directory, password=None, pk=None):
        directory = os.path.abspath(directory)
        if not os.path.isdir(directory):
            raise FileNotFoundError(f"Not a directory: {directory}")
        self.base = directory

        conf_path = os.path.join(directory, 'gocryptfs.conf')
        try:
            raw = open(conf_path, 'rb').read()
        except OSError:
            raise FileNotFoundError(f"Cannot read {conf_path}")
        config = json.loads(raw)

        assert config['Version'] == 2, "Only gocryptfs v2 config supported"
        # FeatureFlags is always a plain list of strings in the real config format
        ff = config['FeatureFlags']
        assert 'HKDF'  in ff, "HKDF feature flag required"
        assert 'FIDO2' not in ff, "FIDO2 is not supported"
        if 'XChaCha20Poly1305' not in ff:
            assert 'GCMIV128' in ff, "GCMIV128 required for AES-GCM vaults"

        self.aessiv        = 'AESSIV'            in ff
        self.xchacha       = 'XChaCha20Poly1305' in ff
        self.plain_names   = 'PlaintextNames'    in ff
        self.raw64         = 'Raw64'             in ff
        self.deterministic = 'DirIV'         not in ff
        # LongNameMax is a top-level field in newer configs, not inside FeatureFlags
        self.longnamemax   = int(config.get('LongNameMax', 255))
        self.config        = config

        if self.raw64 and self.plain_names:
            raise ValueError("Raw64 conflicts with PlaintextNames")

        # Content encryption block overhead
        self._overhead = BLOCK_OVERHEAD + (XCHACHA_EXTRA if self.xchacha else 0)
        self._ezeroed  = bytes(BLOCK_SIZE + self._overhead)

        if pk:
            self.pk = pk
        else:
            if not password:
                raise ValueError("Either password or pk must be provided")
            scrypt  = config['ScryptObject']
            block   = _d64(config['EncryptedKey'])
            kek     = hashlib.scrypt(
                password.encode('utf-8'),
                salt   = _d64(scrypt['Salt']),
                n      = scrypt['N'], r=scrypt['R'], p=scrypt['P'],
                maxmem = 0x7FFFFFFF,
                dklen  = scrypt['KeyLen'],
            )
            key     = HKDF(kek, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_GCM)
            nonce, tag, ct = block[:16], block[-16:], block[16:-16]
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            aes.update(struct.pack(">Q", 0))
            try:
                self.pk = aes.decrypt_and_verify(ct, tag)
            except Exception:
                raise ValueError("Could not decrypt master key – wrong password?")

        # Name encryption engine
        if not self.plain_names and 'EMENames' in ff:
            ek       = HKDF(self.pk, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_EME)
            self._eme = _AES256_EME(ek)
        else:
            self._eme = None

    # -----------------------------------------------------------------------
    # Password management
    # -----------------------------------------------------------------------

    def change_password(self, old_password=None, new_password=None):
        """Re-encrypt the master key with a new password."""
        import getpass
        if old_password is None:
            old_password = getpass.getpass('Current password: ')
        # verify old password
        tmp = Vault(self.base, password=old_password)
        assert tmp.pk == self.pk, "Wrong current password"
        if new_password is None:
            new_password = getpass.getpass('New password: ')
            confirm      = getpass.getpass('Confirm new password: ')
            if new_password != confirm:
                raise ValueError("Passwords do not match")
        # generate new scrypt salt and re-encrypt
        scrypt   = self.config['ScryptObject']
        new_salt = get_random_bytes(32)
        kek      = hashlib.scrypt(
            new_password.encode('utf-8'),
            salt   = new_salt,
            n      = scrypt['N'], r=scrypt['R'], p=scrypt['P'],
            maxmem = 0x7FFFFFFF,
            dklen  = scrypt['KeyLen'],
        )
        key   = HKDF(kek, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_GCM)
        nonce = get_random_bytes(16)
        aes   = AES.new(key, AES.MODE_GCM, nonce=nonce)
        aes.update(struct.pack(">Q", 0))
        ct, tag = aes.encrypt_and_digest(self.pk)
        self.config['ScryptObject']['Salt']  = base64.b64encode(new_salt).decode()
        self.config['EncryptedKey']          = base64.b64encode(nonce + ct + tag).decode()
        conf_path = os.path.join(self.base, 'gocryptfs.conf')
        with open(conf_path, 'w') as fp:
            json.dump(self.config, fp, indent='\t')
        print("Password changed successfully.")

    # -----------------------------------------------------------------------
    # Name encryption / decryption
    # -----------------------------------------------------------------------

    def _encrypt_name(self, iv, name):
        """Encrypt a single name component given its directory IV."""
        if self.plain_names:
            return name
        padded = _pad16(name.encode() if isinstance(name, str) else name)
        if self._eme:
            padded = self._eme.encrypt_iv(iv, padded)
        enc = base64.urlsafe_b64encode(padded)
        if self.raw64:
            enc = enc.rstrip(b'=')
        return enc.decode()

    def _decrypt_name(self, iv, name):
        """Decrypt a single name component given its directory IV.
        On any error returns a placeholder so walk/ls can continue."""
        if self.plain_names:
            return name.decode() if isinstance(name, bytes) else name
        raw_str = name.decode() if isinstance(name, bytes) else name
        # validate alphabet before decoding: gocryptfs uses URL-safe base64
        import re as _re
        if not _re.fullmatch(rb'[A-Za-z0-9_=-]+',
                             name if isinstance(name, bytes) else name.encode()):
            return '<bad-name:' + raw_str[:24] + '>'
        try:
            raw = _d64(name, safe=True)
        except Exception:
            return '<bad-base64:' + raw_str[:24] + '>'
        try:
            if self._eme:
                raw = self._eme.decrypt_iv(iv, raw)
        except Exception:
            return '<eme-error:' + raw_str[:24] + '>'
        plain = _unpad16(raw)
        try:
            return plain.decode()
        except UnicodeDecodeError:
            try:
                return plain.decode('latin-1')
            except Exception:
                return '<encoding-error:' + plain[:12].hex() + '>'

    # -----------------------------------------------------------------------
    # Path resolution
    # -----------------------------------------------------------------------

    def _root_iv(self):
        """Return the IV for the vault root directory."""
        if self.plain_names or self.deterministic:
            return bytes(16)
        ivf = os.path.join(self.base, 'gocryptfs.diriv')
        return open(ivf, 'rb').read(16)

    def _dir_iv(self, real_dir):
        """Return the directory IV stored in *real_dir*.
        Returns 16 zero bytes (with a warning) if missing or corrupt."""
        if self.plain_names or self.deterministic:
            return bytes(16)
        ivf = os.path.join(real_dir, 'gocryptfs.diriv')
        try:
            iv = open(ivf, 'rb').read(16)
        except OSError:
            print('warning: missing gocryptfs.diriv in ' + real_dir + ' -- names will be wrong')
            return bytes(16)
        if len(iv) < 16:
            print('warning: truncated gocryptfs.diriv in ' + real_dir + ' -- names will be wrong')
            return iv.ljust(16, b'\x00')
        return iv

    def getRealPath(self, virtual_path):
        """Resolve a virtual absolute path to its real filesystem path."""
        if not virtual_path.startswith('/'):
            raise ValueError(f"Virtual path must be absolute: {virtual_path!r}")
        rp    = self.base
        parts = [p for p in virtual_path.split('/') if p]
        iv    = self._root_iv()
        for part in parts:
            enc = self._encrypt_name(iv, part)
            if len(enc) > self.longnamemax:
                h   = base64.urlsafe_b64encode(
                    SHA256.new(enc.encode()).digest()
                ).rstrip(b'=').decode()
                enc = f'gocryptfs.longname.{h}'
            rp = os.path.join(rp, enc)
            if os.path.isdir(rp):
                iv = self._dir_iv(rp)
        return rp

    def getVirtualPath(self, real_path):
        """Reverse-resolve a real path back to a virtual path (best-effort)."""
        rel = os.path.relpath(real_path, self.base)
        parts = rel.replace('\\', '/').split('/')
        vp    = ''
        rp    = self.base
        iv    = self._root_iv()
        for enc in parts:
            if enc in ('.', ''):
                continue
            # handle long names
            if enc.startswith('gocryptfs.longname.') and not enc.endswith('.name'):
                name_file = os.path.join(rp, enc + '.name')
                if os.path.exists(name_file):
                    enc = open(name_file).read().strip()
            dec = self._decrypt_name(iv, enc)
            vp  = vp + '/' + dec
            rp  = os.path.join(rp, enc)
            if os.path.isdir(rp):
                iv = self._dir_iv(rp)
        return vp or '/'

    def getInfo(self, virtual_path):
        """Return a :class:`FileInfo` for *virtual_path*."""
        rp        = self.getRealPath(virtual_path)
        exists    = os.path.lexists(rp)
        is_link   = os.path.islink(rp) if exists else False
        # use lstat so we never follow (possibly broken) symlinks
        lstat     = os.lstat(rp) if exists else None
        is_dir    = os.path.isdir(rp) if (exists and not is_link) else False
        return FileInfo(virtual_path, rp, exists, is_dir, lstat, is_link)

    def stat(self, virtual_path):
        """``os.lstat`` on a virtual path (never follows symlinks)."""
        return os.lstat(self.getRealPath(virtual_path))

    # -----------------------------------------------------------------------
    # Directory traversal
    # -----------------------------------------------------------------------

    def walk(self, virtual_path):
        """
        Walk the virtual filesystem like ``os.walk``.
        Yields ``(root_virtual, [dirs], [files])`` tuples.
        """
        real_root = self.getRealPath(virtual_path)
        dir_iv    = self._dir_iv(real_root) if os.path.isdir(real_root) else bytes(16)
        dirs, files = [], []

        skip = {'gocryptfs.diriv', 'gocryptfs.conf'}
        for entry in os.scandir(real_root):
            if entry.name in skip:
                continue
            try:
                enc_name = entry.name
                is_dir   = entry.is_dir(follow_symlinks=False)
                # long name handling
                if enc_name.startswith('gocryptfs.longname.'):
                    if enc_name.endswith('.name'):
                        continue            # metadata sidecar
                    name_file = os.path.join(real_root, enc_name + '.name')
                    if os.path.exists(name_file):
                        try:
                            enc_name = open(name_file).read().strip()
                        except OSError:
                            print('warning: cannot read longname sidecar ' + name_file)
                dec_name = self._decrypt_name(dir_iv, enc_name)
                if is_dir:
                    dirs.append(dec_name)
                else:
                    files.append(dec_name)
            except Exception as e:
                print('warning: skipping ' + entry.name + ': ' + str(e))

        yield virtual_path, sorted(dirs), sorted(files)
        for d in sorted(dirs):
            sub     = virtual_path.rstrip('/') + '/' + d
            real_sub = self.getRealPath(sub)
            if os.path.islink(real_sub):
                continue   # never recurse into symlinked directories
            try:
                yield from self.walk(sub)
            except Exception as e:
                print('warning: cannot descend into ' + sub + ': ' + str(e))

    def glob(self, pattern, root_dir='/'):
        """Return virtual paths matching *pattern* (shell wildcards, no recursion)."""
        import fnmatch
        results = []
        for root, dirs, files in self.walk(root_dir):
            for name in dirs + files:
                full = (root.rstrip('/') + '/' + name)
                if fnmatch.fnmatch(full, pattern) or fnmatch.fnmatch(name, pattern):
                    results.append(full)
            break   # only first level
        return results

    # -----------------------------------------------------------------------
    # Listing
    # -----------------------------------------------------------------------

    def ls(self, vpaths, options=None):
        """
        List virtual paths.

        *options* may carry attributes:
        - ``recursive`` (bool)
        - ``banner``    (bool) – print directory header
        - ``sorting``   (str)  – sort specifier: N(ame) S(ize) D(ate) E(xt) - !
        """
        class _Opt:
            recursive = False
            banner    = True
            sorting   = None

        if options is None:
            options = _Opt()

        for vpath in vpaths:
            for root, dirs, files in self.walk(vpath):
                if options.banner:
                    print(f'\n  Directory of {root}\n')
                all_entries = [(d, True) for d in dirs] + [(f, False) for f in files]
                if options.sorting and all_entries:
                    def _entry_key(entry):
                        name, is_dir = entry
                        full = root.rstrip('/') + '/' + name
                        info = self.getInfo(full)
                        st   = info._stat
                        ext  = os.path.splitext(name)[1].lower()
                        rev  = False
                        keys = []
                        for c in (options.sorting or ''):
                            if c == '-':  rev = True;      continue
                            if c == '!':  rev = not rev;   continue
                            if c == 'N':  keys.append(name.lower())
                            if c == 'S':  keys.append(st.st_size  if st else 0)
                            if c == 'D':  keys.append(st.st_mtime if st else 0)
                            if c == 'E':  keys.append(ext)
                        return keys
                    all_entries.sort(key=_entry_key)
                tot = 0
                for name, is_dir in all_entries:
                    full = root.rstrip('/') + '/' + name
                    info = self.getInfo(full)
                    st   = info._stat
                    ts   = time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime)) if st else '????-??-?? ??:??'
                    if is_dir:
                        print(f'{"<DIR>":>12}  {ts}  {name}/')
                    elif info.isSymlink:
                        print(f'{"<LINK>":>12}  {ts}  {name}')
                    else:
                        sz = _real_plaintext_size(st.st_size if st else 0, self.xchacha)
                        tot += sz
                        print(f'{_fmt_size(sz):>12}  {ts}  {name}')
                print(f'\n{_fmt_size(tot)} bytes in {len(files)} files and {len(dirs)} directories.')
                if not options.recursive:
                    break

    # -----------------------------------------------------------------------
    # Decrypt
    # -----------------------------------------------------------------------

    def _content_key(self):
        """Derive the content encryption key from the master key."""
        if self.aessiv:
            return HKDF(self.pk, salt=b"", key_len=64, hashmod=SHA256, context=S_AES_SIV)
        if self.xchacha:
            return HKDF(self.pk, salt=b"", key_len=32, hashmod=SHA256, context=S_XCHACHA)
        return HKDF(self.pk, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_GCM)

    def _decrypt_block(self, key, blockno, fileid, block):
        """Decrypt a single content block."""
        if block == self._ezeroed:
            return ZEROED_PLAIN
        if self.aessiv:
            nonce, tag, ct = block[:16], block[16:32], block[32:]
            cry = AES.new(key, AES.MODE_SIV, nonce=nonce)
        elif self.xchacha:
            nonce, ct, tag = block[:24], block[24:-16], block[-16:]
            cry = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        else:
            nonce, ct, tag = block[:16], block[16:-16], block[-16:]
            cry = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cry.update(struct.pack('>Q', blockno) + fileid)
        try:
            return cry.decrypt_and_verify(ct, tag)
        except Exception:
            print(f'warning: block {blockno} authentication failed -- block is damaged, filling with zeros')
            return None   # caller will substitute zeros and count the damage

    def _encrypt_block(self, key, blockno, fileid, block):
        """Encrypt a single content block (AES-GCM, AES-SIV, or XChaCha20-Poly1305)."""
        if block == ZEROED_PLAIN:
            return self._ezeroed
        ad = struct.pack('>Q', blockno) + fileid
        if self.aessiv:
            nonce = get_random_bytes(16)
            cry   = AES.new(key, AES.MODE_SIV, nonce=nonce)
            cry.update(ad)
            ct, tag = cry.encrypt_and_digest(block)
            return nonce + tag + ct
        elif self.xchacha:
            nonce = get_random_bytes(24)
            cry   = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            cry.update(ad)
            ct, tag = cry.encrypt_and_digest(block)
            return nonce + ct + tag
        else:
            nonce = get_random_bytes(16)
            cry   = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cry.update(ad)
            ct, tag = cry.encrypt_and_digest(block)
            return nonce + ct + tag

    def decryptFile(self, virtual_src, real_dest, force=False, move=False):
        """
        Decrypt *virtual_src* to *real_dest*.

        Parameters
        ----------
        virtual_src : str  – absolute virtual path
        real_dest   : str  – real filesystem destination path (``-`` = stdout)
        force       : bool – overwrite existing destination
        move        : bool – remove encrypted source after success
        """
        real_src = self.getRealPath(virtual_src)

        if real_dest != '-':
            dest_dir = os.path.dirname(real_dest)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)
            if os.path.exists(real_dest) and not force:
                raise FileExistsError(f'Destination "{real_dest}" already exists (use -f to overwrite)')

        with open(real_src, 'rb') as fp:
            header = fp.read(18)
            if not header:                   # empty plaintext file
                _out = open(real_dest, 'wb') if real_dest != '-' else None
                if _out:
                    _out.close()
                    st = os.stat(real_src)
                    os.utime(real_dest, (st.st_atime, st.st_mtime))
                if move:
                    os.remove(real_src)
                return 0
            if len(header) != 18 or header[:2] != b'\x00\x02':
                raise ValueError(
                    f'Invalid file header in {real_src} '
                    f'(got {header[:2].hex()!r}, expected 0002)'
                )
            fileid = header[2:]
            key    = self._content_key()
            blklen = BLOCK_SIZE + self._overhead

            out = open(real_dest, 'wb') if real_dest != '-' else __import__('sys').stdout.buffer
            damaged_blocks = 0
            n = 0
            try:
                while True:
                    raw = fp.read(blklen)
                    if not raw:
                        break
                    # A short last block is normal for files whose size is
                    # not a multiple of BLOCK_SIZE; pass it as-is.
                    # Only flag it as damaged if it is too short to even
                    # contain the nonce+tag overhead.
                    min_len = self._overhead  # nonce + tag, no payload
                    if 0 < len(raw) < min_len:
                        print(f'warning: block {n} is impossibly short '
                              f'({len(raw)} bytes, minimum is {min_len}) -- skipping')
                        damaged_blocks += 1
                        n += 1
                        continue
                    plain = self._decrypt_block(key, n, fileid, raw)
                    if plain is None:   # _decrypt_block signals unrecoverable damage
                        plain = bytes(BLOCK_SIZE)
                        damaged_blocks += 1
                    out.write(plain)
                    n += 1
            except Exception:
                damaged_blocks += 1
                raise
            finally:
                if real_dest != '-':
                    out.close()
                    if damaged_blocks and os.path.exists(real_dest):
                        # rename to signal partial/damaged output
                        damaged_path = real_dest + '.damaged'
                        try:
                            os.replace(real_dest, damaged_path)
                            print(f'warning: output saved as {damaged_path} due to {damaged_blocks} damaged block(s)')
                            real_dest = damaged_path
                        except OSError:
                            pass
                    if os.path.exists(real_dest):
                        st = os.stat(real_src)
                        os.utime(real_dest, (st.st_atime, st.st_mtime))

        if move:
            os.remove(real_src)
        return os.path.getsize(real_dest) if real_dest != '-' else 0

    def decryptDir(self, virtual_src, real_dest, force=False, move=False, root_dir='/'):
        """Recursively decrypt a virtual directory tree to *real_dest*."""
        if not virtual_src.startswith('/'):
            raise ValueError("Virtual path must be absolute")
        self.getRealPath(virtual_src)   # existence check
        total_bytes = n_files = n_dirs = 0
        T0 = time.time()
        for root, dirs, files in self.walk(virtual_src):
            n_dirs += 1
            for fname in files:
                vfull = root.rstrip('/') + '/' + fname
                dfull = os.path.join(real_dest, vfull.lstrip('/'))
                print(dfull)
                total_bytes += self.decryptFile(vfull, dfull, force, move)
                n_files += 1
        elapsed = time.time() - T0
        print(f'Decrypted {_fmt_size(total_bytes)} bytes in {n_files} files and {n_dirs} directories in {elapsed:.1f}s')

    # -----------------------------------------------------------------------
    # Encrypt
    # -----------------------------------------------------------------------

    def encryptFile(self, real_src, virtual_dest, force=False, move=False):
        """
        Encrypt *real_src* into the vault at *virtual_dest*.

        Parameters
        ----------
        real_src     : str  – real filesystem source path
        virtual_dest : str  – absolute virtual destination path
        force        : bool – overwrite existing encrypted file
        move         : bool – remove plaintext source after success
        """
        real_dest = self.getRealPath(virtual_dest)
        dest_dir  = os.path.dirname(real_dest)
        os.makedirs(dest_dir, exist_ok=True)

        if os.path.exists(real_dest) and not force:
            raise FileExistsError(f'Destination "{virtual_dest}" already exists (use -f to overwrite)')

        key    = self._content_key()
        fileid = get_random_bytes(16)

        with open(real_src, 'rb') as fin, open(real_dest, 'wb') as fout:
            fout.write(b'\x00\x02' + fileid)
            n = 0
            while True:
                block = fin.read(BLOCK_SIZE)
                if not block:
                    break
                fout.write(self._encrypt_block(key, n, fileid, block))
                n += 1

        st = os.stat(real_src)
        os.utime(real_dest, (st.st_atime, st.st_mtime))

        # create parent directory IV if missing (plain-names vaults skip this)
        if not self.plain_names and not self.deterministic:
            self._ensure_diriv(os.path.dirname(real_dest))

        # write longname sidecar if the encrypted name exceeds longnamemax
        self._write_longname_sidecar(virtual_dest)

        if move:
            os.remove(real_src)

    def encryptDir(self, real_src, virtual_dest, force=False, move=False):
        """Recursively encrypt a real directory tree into the vault."""
        for root, dirs, files in os.walk(real_src):
            rel    = os.path.relpath(root, os.path.dirname(real_src)).replace('\\', '/')
            vroot  = virtual_dest.rstrip('/') + '/' + rel
            vroot  = '/' + '/'.join(p for p in vroot.split('/') if p)
            self.mkdir(vroot)
            for fname in files:
                rsrc  = os.path.join(root, fname)
                vdest = vroot.rstrip('/') + '/' + fname
                print(vdest)
                self.encryptFile(rsrc, vdest, force, move)

    # -----------------------------------------------------------------------
    # Directory operations
    # -----------------------------------------------------------------------

    def _ensure_diriv(self, real_dir):
        ivf = os.path.join(real_dir, 'gocryptfs.diriv')
        if not os.path.exists(ivf):
            open(ivf, 'wb').write(get_random_bytes(16))

    def _write_longname_sidecar(self, virtual_path):
        """If *virtual_path* resolves to a longname entry, write the
        accompanying .name sidecar file containing the full encrypted name.
        This is a no-op for names that fit within longnamemax."""
        if not virtual_path.startswith('/'):
            raise ValueError(f'Virtual path must be absolute: {virtual_path!r}')
        rp   = self.base
        parts = [p for p in virtual_path.split('/') if p]
        iv   = self._root_iv()
        for part in parts:
            enc = self._encrypt_name(iv, part)
            if len(enc) > self.longnamemax:
                h         = base64.urlsafe_b64encode(
                    SHA256.new(enc.encode()).digest()
                ).rstrip(b'=').decode()
                real_hash = os.path.join(rp, f'gocryptfs.longname.{h}')
                sidecar   = real_hash + '.name'
                # always (over)write so it stays consistent
                with open(sidecar, 'w') as sf:
                    sf.write(enc)
                rp = real_hash
            else:
                rp = os.path.join(rp, enc)
            if os.path.isdir(rp):
                iv = self._dir_iv(rp)

    def mkdir(self, virtual_path):
        """Create a single virtual directory (and its encrypted counterpart)."""
        parts = [p for p in virtual_path.split('/') if p]
        for i in range(1, len(parts) + 1):
            sub  = '/' + '/'.join(parts[:i])
            rp   = self.getRealPath(sub)
            if not os.path.exists(rp):
                os.mkdir(rp)
                if not self.plain_names and not self.deterministic:
                    self._ensure_diriv(rp)
                # write longname sidecar for this path component if needed
                self._write_longname_sidecar(sub)

    def rmdir(self, virtual_path):
        """Remove an empty virtual directory."""
        rp = self.getRealPath(virtual_path)
        # only diriv inside → truly empty from virtual perspective
        contents = [f for f in os.listdir(rp) if f not in ('gocryptfs.diriv',)]
        if contents:
            raise OSError(f'Directory not empty: {virtual_path}')
        import shutil
        shutil.rmtree(rp)
        if os.path.exists(rp + '.name'):
            os.remove(rp + '.name')

    def rmtree(self, virtual_path):
        """Recursively remove a virtual directory and all its contents."""
        import shutil
        shutil.rmtree(self.getRealPath(virtual_path))

    def remove(self, virtual_path):
        """Remove a virtual file."""
        rp = self.getRealPath(virtual_path)
        # also remove longname sidecar if present
        os.remove(rp)
        if os.path.exists(rp + '.name'):
            os.remove(rp + '.name')

    # -----------------------------------------------------------------------
    # Move / rename
    # -----------------------------------------------------------------------

    def mv(self, virtual_src, virtual_dest):
        """
        Move or rename a virtual file or directory.

        If *virtual_dest* is an existing directory, the source is moved inside it.
        """
        src_info  = self.getInfo(virtual_src)
        dest_info = self.getInfo(virtual_dest)

        if not src_info.exists:
            raise FileNotFoundError(f'Source not found: {virtual_src}')

        real_src  = src_info.realPathName
        if dest_info.exists and dest_info.isDir:
            # move inside the directory
            real_dest = self.getRealPath(
                virtual_dest.rstrip('/') + '/' + os.path.basename(virtual_src)
            )
        else:
            real_dest = dest_info.realPathName

        os.rename(real_src, real_dest)
        # move longname sidecar too, if any
        if os.path.exists(real_src + '.name'):
            os.rename(real_src + '.name', real_dest + '.name')

    # -----------------------------------------------------------------------
    # Symbolic links
    # -----------------------------------------------------------------------

    def ln(self, virtual_target, virtual_link):
        """Create a virtual symlink inside the vault.

        gocryptfs stores symlinks as regular encrypted files whose plaintext
        content is the UTF-8 encoded target path.  No real OS symlink is
        created — this works identically on Windows and Linux.
        """
        import tempfile, os as _os
        # write target path into a temp file, then encrypt it into the vault
        with tempfile.NamedTemporaryFile(delete=False, suffix='.lnk') as tf:
            tf.write(virtual_target.encode('utf-8'))
            tmp_path = tf.name
        try:
            self.encryptFile(tmp_path, virtual_link, force=True)
        finally:
            _os.remove(tmp_path)

    # -----------------------------------------------------------------------
    # Misc helpers
    # -----------------------------------------------------------------------

    def alias(self, virtual_path):
        """Return the real path for a virtual path."""
        return self.getRealPath(virtual_path)



# ---------------------------------------------------------------------------
# Filesystem consistency check (fsck)
# ---------------------------------------------------------------------------

class FsckIssue:
    """Describes a single problem found by fsck."""

    # severity levels
    INFO    = 'INFO'
    WARNING = 'WARNING'
    ERROR   = 'ERROR'

    # issue kinds
    KIND_MISSING_DIRIV     = 'missing_diriv'       # encrypted dir without its diriv
    KIND_TRUNCATED_DIRIV   = 'truncated_diriv'     # diriv shorter than 16 bytes
    KIND_BAD_NAME          = 'bad_name'            # encrypted name that cannot be decoded
    KIND_ORPHAN_LONGNAME   = 'orphan_longname'     # .name sidecar with no matching file/dir
    KIND_MISSING_LONGNAME  = 'missing_longname'    # longname entry with no .name sidecar
    KIND_BAD_HEADER        = 'bad_header'          # file with invalid gocryptfs header
    KIND_BAD_BLOCK         = 'bad_block'           # file with one or more undecryptable blocks
    KIND_TRUNCATED_BLOCK   = 'truncated_block'     # file whose last block is truncated

    def __init__(self, kind, severity, real_path, virtual_path=None, detail=None):
        self.kind         = kind
        self.severity     = severity
        self.real_path    = real_path    # real FS path of the offending item
        self.virtual_path = virtual_path # virtual path if known, else None
        self.detail       = detail       # free-form extra info

    def __str__(self):
        vp  = f'  (virtual: {self.virtual_path})' if self.virtual_path else ''
        det = f'\n    detail: {self.detail}'      if self.detail       else ''
        return f'[{self.severity}] {self.kind}: {self.real_path}{vp}{det}'


def fsck(vault, virtual_root='/', repair=False, interactive=False, verbose=False,
         check_content=False):
    """
    Walk the vault from *virtual_root* and report (and optionally repair)
    every consistency problem found.

    By default performs only a structural check (names, headers, diriv files),
    matching the behaviour of ``gocryptfs -fsck``. Pass ``check_content=True``
    to also authenticate every content block – this is thorough but slow.

    Parameters
    ----------
    vault         : Vault
    virtual_root  : str   – virtual path to start from (default '/')
    repair        : bool  – automatically delete orphan/corrupt items without asking
    interactive   : bool  – ask the user before each deletion (overrides repair)
    verbose       : bool  – also report INFO-level items
    check_content : bool  – authenticate every content block (slow, default False)

    Returns
    -------
    list[FsckIssue]   – all issues found (whether repaired or not)
    """
    import re

    issues   = []
    repaired = []

    def _report(issue):
        issues.append(issue)
        print(str(issue))

    def _ask_delete(real_path, reason):
        """Ask user whether to delete *real_path*. Returns True if deleted."""
        if interactive:
            try:
                ans = input(f'  Delete {real_path}? [y/N] ').strip().lower()
            except EOFError:
                ans = ''
            if ans != 'y':
                return False
        elif not repair:
            return False
        # actually delete
        try:
            import shutil
            if os.path.isdir(real_path):
                shutil.rmtree(real_path)
            else:
                os.remove(real_path)
            repaired.append(real_path)
            print(f'  --> deleted {real_path}')
            return True
        except OSError as e:
            print(f'  --> could not delete {real_path}: {e}')
            return False

    def _check_name(enc_name, real_path, dir_iv):
        """Return decoded name or None if the name is corrupt."""
        if vault.plain_names:
            return enc_name
        if not re.fullmatch(r'[A-Za-z0-9_=-]+', enc_name):
            return None
        try:
            raw = _d64(enc_name.encode(), safe=True)
            if vault._eme:
                raw = vault._eme.decrypt_iv(dir_iv, raw)
            plain = _unpad16(raw)
            return plain.decode()
        except Exception:
            return None

    def _check_file_content(real_path, virtual_path):
        """
        Verify the content blocks of an encrypted file.
        Returns (n_blocks, n_bad, n_truncated).
        """
        n_blocks = n_bad = n_truncated = 0
        try:
            with open(real_path, 'rb') as fp:
                header = fp.read(18)
                if not header:
                    return (0, 0, 0)    # empty file is valid
                if len(header) != 18 or header[:2] != b'\x00\x02':
                    _report(FsckIssue(
                        FsckIssue.KIND_BAD_HEADER, FsckIssue.ERROR,
                        real_path, virtual_path,
                        detail=f'header bytes: {header[:4].hex()!r}'
                    ))
                    return (0, 1, 0)
                fileid = header[2:]
                key    = vault._content_key()
                blklen = BLOCK_SIZE + vault._overhead
                n = 0
                while True:
                    raw = fp.read(blklen)
                    if not raw:
                        break
                    n_blocks += 1
                    min_len = vault._overhead
                    if 0 < len(raw) < min_len:
                        # impossibly short: genuine corruption
                        n_truncated += 1
                        n += 1
                        continue
                    if len(raw) == blklen or len(raw) >= min_len:
                        # attempt authentication without writing output
                        if raw != vault._ezeroed:
                            if vault.aessiv:
                                from_cipher = lambda r: (r[:16], r[16:32], r[32:])
                                nonce, tag, ct = from_cipher(raw)
                                try:
                                    AES.new(key, AES.MODE_SIV, nonce=nonce).update(
                                        struct.pack('>Q', n) + fileid
                                    )
                                except Exception:
                                    pass
                            elif vault.xchacha:
                                nonce, ct, tag = raw[:24], raw[24:-16], raw[-16:]
                                cry = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                                cry.update(struct.pack('>Q', n) + fileid)
                            else:
                                nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
                                cry = AES.new(key, AES.MODE_GCM, nonce=nonce)
                                cry.update(struct.pack('>Q', n) + fileid)
                            try:
                                cry.decrypt_and_verify(ct, tag)
                            except Exception:
                                n_bad += 1
                    n += 1
        except OSError as e:
            _report(FsckIssue(
                FsckIssue.KIND_BAD_HEADER, FsckIssue.ERROR,
                real_path, virtual_path, detail=str(e)
            ))
        return (n_blocks, n_bad, n_truncated)

    # ── main scan ──────────────────────────────────────────────────────────
    print(f'\nFsck of vault {vault.base} starting from {virtual_root}\n')

    # We walk the real filesystem directly so we can catch issues that
    # would be hidden or cause crashes in the virtual walk.
    real_root = vault.getRealPath(virtual_root)

    for real_dir, subdirs, filenames in os.walk(real_root):
        # virtual path of this real directory
        try:
            vdir = vault.getVirtualPath(real_dir)
        except Exception:
            vdir = None

        # ── 1. diriv checks ───────────────────────────────────────────────
        has_diriv = 'gocryptfs.diriv' in filenames
        if not vault.plain_names and not vault.deterministic:
            if not has_diriv:
                issue = FsckIssue(
                    FsckIssue.KIND_MISSING_DIRIV, FsckIssue.ERROR,
                    real_dir, vdir,
                    detail='directory IV file is missing – names in this dir cannot be recovered'
                )
                _report(issue)
                # without diriv we cannot validate names; mark subdirs for skipping
                subdirs[:] = []
                continue
            else:
                ivf = os.path.join(real_dir, 'gocryptfs.diriv')
                iv_data = open(ivf, 'rb').read()
                if len(iv_data) < 16:
                    issue = FsckIssue(
                        FsckIssue.KIND_TRUNCATED_DIRIV, FsckIssue.ERROR,
                        ivf, vdir,
                        detail=f'only {len(iv_data)}/16 bytes'
                    )
                    _report(issue)
                    dir_iv = iv_data.ljust(16, b'\x00')
                else:
                    dir_iv = iv_data[:16]
        else:
            dir_iv = bytes(16)

        # ── 2. per-entry checks ───────────────────────────────────────────
        all_entries = [(f, False) for f in filenames] + [(d, True) for d in subdirs[:]]

        # collect longname hash stems present in this directory
        longname_hashes = set()
        for fname in filenames:
            if fname.startswith('gocryptfs.longname.') and fname.endswith('.name'):
                longname_hashes.add(fname[len('gocryptfs.longname.'):-len('.name')])

        for enc_name, entry_is_dir in all_entries:
            if enc_name in ('gocryptfs.diriv', 'gocryptfs.conf'):
                continue

            real_entry = os.path.join(real_dir, enc_name)

            # ── longname sidecar (.name) without matching content file ────
            if enc_name.startswith('gocryptfs.longname.') and enc_name.endswith('.name'):
                hash_part = enc_name[len('gocryptfs.longname.'):-len('.name')]
                content   = os.path.join(real_dir, 'gocryptfs.longname.' + hash_part)
                if not os.path.exists(content):
                    issue = FsckIssue(
                        FsckIssue.KIND_ORPHAN_LONGNAME, FsckIssue.WARNING,
                        real_entry, vdir,
                        detail='longname .name sidecar has no matching content file'
                    )
                    _report(issue)
                    _ask_delete(real_entry, 'orphan .name sidecar')
                continue

            # ── longname content without .name sidecar ────────────────────
            if enc_name.startswith('gocryptfs.longname.') and not enc_name.endswith('.name'):
                hash_part = enc_name[len('gocryptfs.longname.'):]
                if hash_part not in longname_hashes:
                    issue = FsckIssue(
                        FsckIssue.KIND_MISSING_LONGNAME, FsckIssue.ERROR,
                        real_entry, vdir,
                        detail='longname content file has no .name sidecar – name is unrecoverable'
                    )
                    _report(issue)
                    _ask_delete(real_entry, 'longname with missing sidecar')
                    if entry_is_dir:
                        subdirs[:] = [d for d in subdirs if d != enc_name]
                continue

            # ── bad encrypted name ─────────────────────────────────────────
            dec_name = _check_name(enc_name, real_entry, dir_iv)
            if dec_name is None:
                issue = FsckIssue(
                    FsckIssue.KIND_BAD_NAME, FsckIssue.ERROR,
                    real_entry, vdir,
                    detail=f'encrypted name {enc_name!r} cannot be decrypted'
                )
                _report(issue)
                _ask_delete(real_entry, 'undecryptable name')
                if entry_is_dir:
                    subdirs[:] = [d for d in subdirs if d != enc_name]
                continue

            virtual_entry = (vdir or '/').rstrip('/') + '/' + dec_name

            # ── file header check (always) ────────────────────────────────
            if not entry_is_dir:
                try:
                    with open(real_entry, 'rb') as _fh:
                        _hdr = _fh.read(18)
                    if _hdr and (len(_hdr) != 18 or _hdr[:2] != b'\x00\x02'):
                        issue = FsckIssue(
                            FsckIssue.KIND_BAD_HEADER, FsckIssue.ERROR,
                            real_entry, virtual_entry,
                            detail=f'header bytes: {_hdr[:4].hex()!r}'
                        )
                        _report(issue)
                        _ask_delete(real_entry, 'file with invalid header')
                        continue
                except OSError as _e:
                    _report(FsckIssue(FsckIssue.KIND_BAD_HEADER, FsckIssue.ERROR,
                                      real_entry, virtual_entry, detail=str(_e)))
                    continue

            # ── file content check (only if -c / check_content=True) ──────
            if not entry_is_dir and check_content:
                n_blocks, n_bad, n_trunc = _check_file_content(real_entry, virtual_entry)
                if n_bad:
                    issue = FsckIssue(
                        FsckIssue.KIND_BAD_BLOCK, FsckIssue.ERROR,
                        real_entry, virtual_entry,
                        detail=f'{n_bad}/{n_blocks} block(s) failed authentication'
                    )
                    _report(issue)
                    _ask_delete(real_entry, 'file with corrupt blocks')
                elif n_trunc:
                    issue = FsckIssue(
                        FsckIssue.KIND_TRUNCATED_BLOCK, FsckIssue.WARNING,
                        real_entry, virtual_entry,
                        detail=f'last block is truncated ({n_trunc} occurrence(s))'
                    )
                    _report(issue)
                    _ask_delete(real_entry, 'file with truncated last block')

    # ── summary ───────────────────────────────────────────────────────────
    errors   = [i for i in issues if i.severity == FsckIssue.ERROR]
    warnings = [i for i in issues if i.severity == FsckIssue.WARNING]
    mode_str = 'structural + content' if check_content else 'structural only'
    print(f'\nFsck complete ({mode_str}): {len(errors)} error(s), {len(warnings)} warning(s).')
    if repaired:
        print(f'{len(repaired)} item(s) deleted.')
    if not issues:
        print('No problems found.')
    return issues


# ---------------------------------------------------------------------------
# Vault initialisation
# ---------------------------------------------------------------------------

def init_vault(
    directory,
    password    = None,
    # content cipher (mutually exclusive)
    aessiv      = False,
    xchacha     = False,
    # name handling
    plain_names = False,
    # per-directory IVs (False = legacy deterministic mode)
    diriv       = True,
    # base64url without padding for encrypted names
    raw64       = True,
    # longname threshold (63 / 127 / 175 / 255)
    longnamemax = 255,
    # scrypt cost parameter N expressed as log2(N), default 16 -> N=65536
    scryptn     = 16,
):
    """
    Initialise a new gocryptfs v2 vault in *directory*.

    Parameters
    ----------
    aessiv      : use AES-SIV instead of AES-GCM (nonce-misuse resistant)
    xchacha     : use XChaCha20-Poly1305 instead of AES-GCM (faster without AES-NI)
    plain_names : store filenames in plaintext (no EME encryption)
    diriv       : per-directory random IVs (default True; False = legacy deterministic)
    raw64       : unpadded base64url for encrypted names (default True)
    longnamemax : longname sidecar threshold; allowed: 63, 127, 175, 255 (default 255)
    scryptn     : scrypt cost as log2(N), matching gocryptfs -scryptn (default 16 = N/65536).
                  Range 10..28.  Higher = slower mount but stronger against brute-force.
    """
    import getpass

    # mutually exclusive cipher options
    if aessiv and xchacha:
        raise ValueError("--cipher aes-siv and --cipher xchacha are mutually exclusive")

    # plain_names makes name-encryption options meaningless or contradictory
    if plain_names and raw64:
        raise ValueError("--plain-names and --no-raw64 / raw64 are mutually exclusive: "
                         "raw64 only applies to encrypted names")
    if plain_names and not diriv:
        raise ValueError("--plain-names and --no-diriv are mutually exclusive: "
                         "DirIV is not used with plaintext names regardless")

    # range checks
    if not (62 <= longnamemax <= 255):
        raise ValueError("longnamemax must be between 62 and 255")
    if not (10 <= scryptn <= 28):
        raise ValueError("scryptn must be between 10 and 28")

    os.makedirs(directory, exist_ok=True)
    if any(f for f in os.listdir(directory) if not f.startswith('.')):
        raise FileExistsError(f'{directory} is not empty')

    if not password:
        password = getpass.getpass('New vault password: ')
        confirm  = getpass.getpass('Confirm password: ')
        if password != confirm:
            raise ValueError('Passwords do not match')

    N = 1 << scryptn
    r, p, L = 8, 1, 32

    masterkey = get_random_bytes(32)
    salt      = get_random_bytes(32)
    # OpenSSL uses a 32-bit C long for maxmem even on 64-bit Windows,
    # so 0x7FFFFFFF (2 GiB - 1) is the safe ceiling on all platforms.
    kek       = hashlib.scrypt(password.encode(), salt=salt, n=N, r=r, p=p,
                               maxmem=0x7FFFFFFF, dklen=L)
    enc_key   = HKDF(kek, salt=b"", key_len=32, hashmod=SHA256, context=S_AES_GCM)
    nonce     = get_random_bytes(16)
    aes_obj   = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
    aes_obj.update(struct.pack(">Q", 0))
    ct, tag   = aes_obj.encrypt_and_digest(masterkey)

    # build FeatureFlags
    # GCMIV128 is specific to AES-GCM; XChaCha20Poly1305 conflicts with it
    flags = ["HKDF"]
    if xchacha:
        flags.append("XChaCha20Poly1305")
    else:
        flags.append("GCMIV128")
        if aessiv:
            flags.append("AESSIV")
    if plain_names:
        flags.append("PlaintextNames")
    else:
        flags.append("EMENames")
    if diriv:
        flags.append("DirIV")
    if raw64 and not plain_names:
        flags.append("Raw64")
    if not plain_names:
        flags.append("LongNames")

    config = {
        "Creator":      "pygocryptfs",
        "EncryptedKey": base64.b64encode(nonce + ct + tag).decode(),
        "ScryptObject": {
            "Salt":   base64.b64encode(salt).decode(),
            "N": N, "R": r, "P": p, "KeyLen": L,
        },
        "Version":      2,
        "FeatureFlags": flags,
    }
    # LongNameMax is omitempty: only written when non-default (< 255)
    if longnamemax < 255:
        config["LongNameMax"] = longnamemax
    conf_path = os.path.join(directory, 'gocryptfs.conf')
    with open(conf_path, 'w') as fp:
        json.dump(config, fp, indent='\t')

    # root diriv (only in DirIV mode)
    if diriv and not plain_names:
        root_ivf = os.path.join(directory, 'gocryptfs.diriv')
        open(root_ivf, 'wb').write(get_random_bytes(16))

    cipher = 'AES-SIV' if aessiv else ('XChaCha20-Poly1305' if xchacha else 'AES-GCM')
    names  = 'plaintext' if plain_names else f'EME-encrypted (longnamemax={longnamemax})'
    print(f'Vault initialised in {directory}')
    print(f'  Cipher : {cipher}')
    print(f'  Names  : {names}')
    print(f'  DirIV  : {"yes" if diriv else "no (legacy/deterministic)"}')
    print(f'  Scrypt : scryptn={scryptn} (N={N}) r={r} p={p}')




# ---------------------------------------------------------------------------
# Vault info
# ---------------------------------------------------------------------------

def print_vault_info(directory):
    """
    Pretty-print the vault configuration, matching gocryptfs -info output.
    Sensitive data (EncryptedKey, Salt) is omitted.
    """
    conf_path = os.path.join(directory, 'gocryptfs.conf')
    try:
        config = json.loads(open(conf_path, 'rb').read())
    except OSError:
        raise FileNotFoundError(f"Cannot read {conf_path}")

    ff      = config.get('FeatureFlags', [])
    scrypt  = config.get('ScryptObject', {})
    version = config.get('Version', '?')
    lnmax   = config.get('LongNameMax', 255)

    creator = config.get('Creator', '(unknown)')
    print(f"Creator:       {creator}")
    print(f"Version:       {version}")
    print(f"FeatureFlags:  {' '.join(ff)}")
    print(f"LongNameMax:   {lnmax}")
    N = scrypt.get('N', '?')
    scryptn = N.bit_length() - 1 if isinstance(N, int) and N > 0 else '?'
    print(f"ScryptObject:  N={N} (scryptn={scryptn}) R={scrypt.get('R','?')} P={scrypt.get('P','?')} KeyLen={scrypt.get('KeyLen','?')}")

# ---------------------------------------------------------------------------
# Directory-IV backup
# ---------------------------------------------------------------------------

def backupDirIds(vault_base, zip_path):
    """
    Archive all ``gocryptfs.diriv`` files (with their encrypted path structure)
    into a ZIP for recovery purposes.
    """
    if not os.path.isdir(vault_base) or \
       not os.path.exists(os.path.join(vault_base, 'gocryptfs.conf')):
        raise ValueError(f'{vault_base} is not a valid gocryptfs vault')
    base_len = len(vault_base)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(vault_base):
            if 'gocryptfs.diriv' in files:
                rel = os.path.join(root[base_len + 1:], 'gocryptfs.diriv')
                zf.write(os.path.join(root, 'gocryptfs.diriv'), rel)
    print(f'Directory IVs backed up to {zip_path}')
