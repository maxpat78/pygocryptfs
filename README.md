# pygocryptfs

A Python toolkit for **gocryptfs v2** encrypted filesystems, inspired by [pycryptomator](https://github.com/maxpat78/pycryptomator).

Provides full programmatic and shell-based access to a gocryptfs vault **without** needing the FUSE driver installed.
Works on Windows, Linux and macOS.

---

## Requirements

- Python ≥ 3.10
- `pycryptodome` or `pycryptodomeX`

```bash
pip install pycryptodome
```

---

## Supported feature flags

| Flag | Status |
|---|---|
| HKDF + GCMIV128 | ✅ required baseline |
| EMENames + DirIV | ✅ per-directory IV + EME wide-block name encryption (default) |
| Raw64 | ✅ unpadded base64url names |
| LongNames + LongNameMax | ✅ configurable long-name sidecar threshold |
| PlaintextNames | ✅ unencrypted names |
| AESSIV | ✅ AES-SIV content encryption |
| XChaCha20Poly1305 | ✅ XChaCha20-Poly1305 content encryption (gocryptfs ≥ 2.2) |
| FIDO2 | ❌ not supported |
| Reverse mode | ❌ not supported |
| gocryptfs v1 (no HKDF) | ❌ not supported |

---

## Interactive shell

```bash
python -m pygocryptfs /path/to/vault
# or with explicit password
python -m pygocryptfs --password mypassword /path/to/vault
```

The shell understands these commands:

| Command | Description |
|---|---|
| `ls [-b] [-r] [-s NSDE-!] [path ...]` | List virtual directory contents |
| `cd <dir>` | Change current virtual directory |
| `pwd` | Print current virtual directory |
| `cat <file>` | Decrypt a file to stdout |
| `decrypt [-f] [-m] [-F] <vsrc> ... <real_dest>` | Decrypt file(s)/dir(s) to the real filesystem |
| `encrypt [-f] [-m] [-F] <real_src> ... <vdest>` | Encrypt file(s)/dir(s) into the vault |
| `mkdir [-R] <dir> [...]` | Create virtual directory/ies |
| `mv <src> [src2 ...] <dest>` | Move / rename |
| `rm [-f] <path> [...]` | Remove file(s)/dir(s) (`-f` = force recursive) |
| `alias <vpath> [...]` | Show real (encrypted) pathname of a virtual path |
| `backup <zip>` | Backup all `gocryptfs.diriv` files to a ZIP archive |
| `fsck [-r] [-f] [-i] [-v] [-c] [path]` | Check vault integrity (see below) |
| `quit` / `exit` | Exit the shell |

Shell wildcards (`*`, `?`) are supported for all commands.

### `ls` sort specifiers (`-s`)

| Char | Meaning |
|---|---|
| `N` | by Name |
| `S` | by Size |
| `D` | by Date |
| `E` | by Extension |
| `-` | reverse the subsequent key |
| `!` | toggle reverse |

---

## Single-command mode

```bash
python -m pygocryptfs --password secret /vault ls /
python -m pygocryptfs --password secret /vault decrypt /secret.txt /tmp/out.txt
python -m pygocryptfs --password secret /vault encrypt /tmp/myfile.txt /
```

On Windows, wildcards in source paths are expanded by pygocryptfs (the Windows shell does not expand them):

```
py -m pygocryptfs --password secret myvault encrypt docs\*.pdf /documents
```

---

## Initialise a new vault

```bash
python -m pygocryptfs --init /path/to/new/vault
```

All options mirror the official gocryptfs CLI:

| Option | Default | Description |
|---|---|---|
| `--cipher aes-gcm\|aes-siv\|xchacha` | `aes-gcm` | Content encryption cipher |
| `--plain-names` | off | Store filenames in plaintext (no EME encryption) |
| `--no-diriv` | off | Disable per-directory IVs (legacy deterministic mode) |
| `--no-raw64` | off | Use padded base64 instead of raw64url for encrypted names |
| `--longnamemax N` | `255` | Max encrypted name length before longname sidecar (62–255) |
| `--scryptn N` | `16` | Scrypt cost as log2(N), like gocryptfs `-scryptn` (range 10–28) |
| `--password` | prompted | Password for the new vault |
| `--passfile FILE` | — | Read password from first line of FILE |
| `--extpass PROGRAM` | — | Read password from stdout of PROGRAM |

Examples:

```bash
# Standard vault (equivalent to gocryptfs defaults)
python -m pygocryptfs --init myvault

# AES-SIV cipher, stronger key derivation
python -m pygocryptfs --init --cipher aes-siv --scryptn 18 myvault

# XChaCha20 (faster on hardware without AES-NI)
python -m pygocryptfs --init --cipher xchacha myvault

# Plaintext names, no DirIV (legacy mode)
python -m pygocryptfs --init --plain-names myvault

# Short names (useful on filesystems with filename length limits)
python -m pygocryptfs --init --longnamemax 100 myvault
```

---

## Show vault configuration

Prints the vault configuration without requiring the password (like `gocryptfs -info`):

```bash
python -m pygocryptfs --info /path/to/vault
```

Example output:

```
Creator:       gocryptfs v2.4.0
Version:       2
FeatureFlags:  HKDF GCMIV128 EMENames DirIV Raw64 LongNames
LongNameMax:   255
ScryptObject:  N=65536 (scryptn=16) R=8 P=1 KeyLen=32
```

---

## Check vault integrity (`fsck`)

Structural check (fast — verifies names, headers, diriv files):

```bash
python -m pygocryptfs --fsck /vault
# or inside the shell:
fsck
```

Full check including content block authentication (slow):

```bash
python -m pygocryptfs --fsck full /vault
```

`--fsck` modes:

| Mode | Description |
|---|---|
| `check` | Structural only, no deletions (default) |
| `ask` | Structural + prompt before each deletion |
| `repair` | Structural + auto-delete corrupt items |
| `full` | `repair` + authenticate every content block (slow) |

Inside the shell, `fsck` accepts flags directly:

```
fsck -c          # full content check
fsck -r          # auto-repair
fsck -i          # interactive repair
fsck /subdir     # check a subtree only
```

---

## Unlock options

```bash
# Password on command line
python -m pygocryptfs --password secret /vault

# Password from a file
python -m pygocryptfs --passfile ~/.vault_password /vault

# Password from an external program
python -m pygocryptfs --extpass "gpg --decrypt pass.gpg" /vault

# Using the raw master key (recovery)
python -m pygocryptfs --master-key aabbccdd-eeff0011-... /vault
```

---

## Print / backup the master key

```bash
# Print in hex (default)
python -m pygocryptfs --password secret --print-key     /vault
# Print in base64
python -m pygocryptfs --password secret --print-key b64 /vault
# Print in ASCII85
python -m pygocryptfs --password secret --print-key a85 /vault
```

---

## Change the vault password

```bash
python -m pygocryptfs --password oldpass --change-password /vault
```

---

## Programmatic API

```python
from pygocryptfs import Vault, init_vault, backupDirIds, fsck, print_vault_info

# Open an existing vault
v = Vault('/path/to/vault', password='secret')

# List root
v.ls(['/'])

# Decrypt a file
v.decryptFile('/documents/report.pdf', '/tmp/report.pdf', force=True)

# Encrypt a file
v.encryptFile('/tmp/photo.jpg', '/photos/photo.jpg')

# Walk the virtual filesystem
for root, dirs, files in v.walk('/'):
    print(root, dirs, files)

# Create a directory
v.mkdir('/new_folder')

# Move / rename
v.mv('/old_name.txt', '/new_name.txt')

# Remove
v.remove('/unwanted.txt')
v.rmtree('/old_folder')

# Check vault integrity
fsck(v)                          # structural only
fsck(v, check_content=True)      # full content check
fsck(v, repair=True)             # auto-repair

# Backup directory IVs
backupDirIds('/path/to/vault', '/tmp/diriv_backup.zip')

# Show vault configuration (no password needed)
print_vault_info('/path/to/vault')

# Initialise a new vault
init_vault('/path/to/new/vault', password='secret', scryptn=18)
```

---

## Package structure

```
pygocryptfs/
├── __init__.py       # public API
├── __main__.py       # CLI entry point
├── gocryptfs.py      # Vault class + all crypto logic
├── gcshell.py        # interactive shell (GCShell)
└── w32lex.py         # Windows command-line lexer
```

---

## License

MIT License – see source files for copyright notices.
