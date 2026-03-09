# -*- coding: utf-8 -*-
"""
pygocryptfs
~~~~~~~~~~~
Python toolkit for gocryptfs v2 encrypted filesystems.

Provides read/write access (list, encrypt, decrypt, rename, move, remove)
to gocryptfs vaults without requiring the FUSE driver.

Supported feature flags
-----------------------
- HKDF, GCMIV128  (mandatory baseline)
- EMENames + DirIV (per-directory IV, EME wide-block name encryption) [default]
- Raw64            (unpadded base64 encoded names)
- PlaintextNames   (no name encryption)
- AESSIV           (AES-SIV content encryption)
- XChaCha20Poly1305 (XChaCha20 content encryption, gocryptfs ≥ 2.2)
- LongNameMax      (custom longname threshold)

NOT supported
-------------
- FIDO2 authentication
- Reverse mode
- gocryptfs v1 (no HKDF)

MIT License – Copyright (c) 2024-26 maxpat78
"""
__version__ = '1.0'
COPYRIGHT   = 'Copyright (C) 2024-26 maxpat78'
__all__     = ['Vault', 'init_vault', 'backupDirIds', 'fsck', 'FsckIssue', 'print_vault_info']
from .gocryptfs import Vault, init_vault, backupDirIds, fsck, FsckIssue, print_vault_info
