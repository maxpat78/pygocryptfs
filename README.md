# pygocryptfs

A Python toolkit for **gocryptfs v2** encrypted filesystems, inspired by [pycryptomator](https://github.com/maxpat78/pycryptomator).

Provides full programmatic and shell-based access to a gocryptfs vault **without** needing the FUSE driver installed.

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
| Raw64 | ✅ unpadded base64 names |
| PlaintextNames | ✅ unencrypted names |
| AESSIV | ✅ AES-SIV content encryption |
| XChaCha20Poly1305 | ✅ XChaCha20 content encryption (gocryptfs ≥ 2.2) |
| LongNameMax | ✅ configurable long-name threshold |
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
| `decrypt [-f] [-m] [-F] <vsrc> ... <real_dest>` | Decrypt file(s)/dir(s) to the real FS |
| `encrypt [-f] [-m] [-F] <real_src> ... <vdest>` | Encrypt file(s)/dir(s) into the vault |
| `mkdir [-R] <dir> [...]` | Create virtual directory/ies |
| `mv <src> [src2 ...] <dest>` | Move / rename |
| `rm [-f] <path> [...]` | Remove file(s)/dir(s) (`-f` = force recursive) |
| `alias <vpath> [...]` | Show real pathname of a virtual path |
| `backup <zip>` | Backup all `gocryptfs.diriv` to a ZIP |
| `quit` / `exit` | Exit the shell |

Shell wildcards (`*`, `?`) are supported for all commands.

### `ls` sort specifiers

| Char | Meaning |
|---|---|
| `N` | by Name |
| `S` | by Size |
| `D` | by Date |
| `E` | by Extension |
| `-` | reverse subsequent key |
| `!` | toggle reverse |

---

## Single-command mode

```bash
python -m pygocryptfs --password secret /vault ls /
python -m pygocryptfs --password secret /vault decrypt /secret.txt /tmp/out.txt
python -m pygocryptfs --password secret /vault encrypt /tmp/myfile.txt /
```

---

## Initialise a new vault

```bash
python -m pygocryptfs --init --password mypassword /path/to/new/vault
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
from pygocryptfs import Vault, init_vault, backupDirIds

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

# Backup directory IVs
backupDirIds('/path/to/vault', '/tmp/diriv_backup.zip')
```

---

## Package structure

```
pygocryptfs/
├── __init__.py       # public API: Vault, init_vault, backupDirIds
├── __main__.py       # CLI entry point
├── gocryptfs.py      # Vault class + all crypto logic
└── gcshell.py        # Interactive shell (GCShell)
```

---

## License

MIT License – see source files for copyright notices.
