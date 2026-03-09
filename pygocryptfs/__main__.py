# -*- coding: utf-8 -*-
"""
pygocryptfs.__main__
~~~~~~~~~~~~~~~~~~~~
Command-line entry point.

Usage examples
--------------
  python -m pygocryptfs --init            /path/to/new/vault
  python -m pygocryptfs --print-key b64  /path/to/vault
  python -m pygocryptfs --password secret /path/to/vault
  python -m pygocryptfs --password secret /path/to/vault  ls /
  python -m pygocryptfs --password secret /path/to/vault  decrypt /secret.txt /tmp/out.txt

MIT License – Copyright (c) 2024-26 maxpat78
"""

import argparse
import base64
import getpass
import locale
import os
import sys

# Capture the real working directory immediately, before anything changes it.
# This is what the user expects relative paths to be resolved against.
_LAUNCH_CWD = os.getcwd()

from os.path import exists, dirname, join

from .gocryptfs import Vault, init_vault, backupDirIds, fsck, FsckIssue, print_vault_info
from .gcshell   import GCShell

if os.name == 'nt':
    try:
        import pygocryptfs.w32lex as shlex
    except ImportError:
        import shlex
else:
    import shlex

locale.setlocale(locale.LC_ALL, '')

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    prog='pygocryptfs',
    description='Access a gocryptfs v2 encrypted filesystem',
)
parser.add_argument(
    '--init', action='store_true',
    help='Initialise a new vault in an empty directory',
)
# ── --init options (ignored unless --init is given) ─────────────────────────
_init = parser.add_argument_group('vault creation options (only with --init)')
_init.add_argument(
    '--cipher',
    metavar='aes-gcm|aes-siv|xchacha',
    choices=['aes-gcm', 'aes-siv', 'xchacha'], default='aes-gcm',
    help='Content cipher  [default: aes-gcm]',
)
_init.add_argument(
    '--plain-names', action='store_true',
    help='Store filenames in plaintext (no EME encryption)',
)
_init.add_argument(
    '--no-diriv', action='store_true',
    help='Disable per-directory IVs (legacy deterministic mode)',
)
_init.add_argument(
    '--no-raw64', action='store_true',
    help='Use padded base64 instead of raw64 for encrypted names',
)
_init.add_argument(
    '--longnamemax',
    metavar='N', type=int, default=255,
    help='Max encrypted name length before longname sidecar, 62..255  [default: 255]',
)
_init.add_argument(
    '--scryptn',
    metavar='N', type=int, default=16,
    help=(
        'Scrypt cost as log2(N), like gocryptfs -scryptn  [default: 16 = N/65536]  '
        'Range 10..28.  Higher = slower but stronger against brute-force.'
    ),
)
parser.add_argument(
    'vault_path',
    help='Path to the gocryptfs vault directory',
)
parser.add_argument(
    '--print-key',
    metavar='hex|b64|a85', choices=['hex', 'b64', 'a85'],
    nargs='?', const='hex', default=None,
    help='Print the master key: hex (default), b64 (Base64), a85 (ASCII85)',
)
parser.add_argument(
    '--master-key',
    metavar='MASTER_KEY',
    help='Master key as hex string (groups separated by - are ignored)',
)
parser.add_argument(
    '--password',
    help='Password to unlock the master key from the config file',
)
parser.add_argument(
    '--passfile',
    metavar='FILE',
    help='Read password from the first line of FILE (like gocryptfs -passfile)',
)
parser.add_argument(
    '--extpass',
    metavar='PROGRAM',
    help='Read password from stdout of PROGRAM (like gocryptfs -extpass)',
)
parser.add_argument(
    '--change-password', action='store_true',
    help='Change the vault password',
)
parser.add_argument(
    '--info', action='store_true',
    help='Pretty-print the vault configuration (like gocryptfs -info)',
)
parser.add_argument(
    '--fsck',
    metavar='check|ask|repair|full',
    nargs='?', const='check', default=None,
    choices=['check', 'ask', 'repair', 'full'],
    help=(
        'Check vault integrity. Modes: '
        'check = structural only, no deletions (default); '
        'ask   = structural + prompt before each deletion; '
        'repair = structural + auto-delete corrupt items; '
        'full  = repair + authenticate every content block (slow)'
    ),
)

args, extras = parser.parse_known_args()

# ---------------------------------------------------------------------------
# Vault initialisation
# ---------------------------------------------------------------------------

if args.info:
    try:
        print_vault_info(args.vault_path)
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)
    sys.exit(0)

if args.init:
    # Validate mutually exclusive --init options early for a clean error message
    if args.cipher == 'aes-siv' and args.plain_names:
        parser.error("--cipher aes-siv and --plain-names are mutually exclusive")
    if args.plain_names and not args.no_raw64:
        # raw64=True is the default; silently override rather than error,
        # since plain_names simply makes raw64 irrelevant
        args.no_raw64 = True
    if args.plain_names and args.no_diriv:
        parser.error("--plain-names and --no-diriv are mutually exclusive")
    init_vault(
        args.vault_path,
        password    = args.password,
        aessiv      = args.cipher == 'aes-siv',
        xchacha     = args.cipher == 'xchacha',
        plain_names = args.plain_names,
        diriv       = not args.no_diriv,
        raw64       = not args.no_raw64,
        longnamemax = args.longnamemax,
        scryptn     = args.scryptn,
    )
    sys.exit(0)

if not exists(args.vault_path):
    print(f'Vault not found: {args.vault_path}')
    sys.exit(1)

# ---------------------------------------------------------------------------
# Open vault
# ---------------------------------------------------------------------------

if not args.password and args.passfile:
    try:
        args.password = open(args.passfile).readline().rstrip('\n')
    except OSError as e:
        print(f'Cannot read passfile: {e}')
        sys.exit(1)
elif not args.password and args.extpass:
    import subprocess
    try:
        args.password = subprocess.check_output(
            args.extpass, shell=True, text=True
        ).rstrip('\n')
    except subprocess.CalledProcessError as e:
        print(f'extpass failed: {e}')
        sys.exit(1)

if not args.password and not args.master_key:
    args.password = getpass.getpass('Password: ')

if args.master_key:
    # Accept hex strings like "aabbcc" or "aa-bb-cc-..."
    try:
        pk = bytes.fromhex(args.master_key.replace('-', ''))
    except ValueError:
        # fall back to base64 / ASCII85
        try:
            pk = base64.a85decode(args.master_key)
        except Exception:
            pk = base64.urlsafe_b64decode(args.master_key + '==')
    v = Vault(args.vault_path, pk=pk)
else:
    v = Vault(args.vault_path, password=args.password)

# ---------------------------------------------------------------------------
# --print-key
# ---------------------------------------------------------------------------

if args.print_key is not None:
    print('\n   * * *  WARNING !!!  * * *\n')
    print('KEEP THIS KEY TOP SECRET!\nFor recovering purposes only.\n')
    fmt = args.print_key or 'hex'
    if fmt == 'hex':
        groups = [v.pk[i:i+4].hex() for i in range(0, len(v.pk), 4)]
        print('Master key:', '-'.join(groups))
    elif fmt == 'a85':
        print('Master key:', base64.a85encode(v.pk).decode())
    else:
        print('Master key:', base64.urlsafe_b64encode(v.pk).decode())
    sys.exit(0)

# ---------------------------------------------------------------------------
# --change-password
# ---------------------------------------------------------------------------

if args.change_password:
    v.change_password(old_password=args.password)
    sys.exit(0)

if args.fsck is not None:
    fsck(v,
         repair        = args.fsck in ('repair', 'full'),
         interactive   = args.fsck == 'ask',
         check_content = args.fsck == 'full')
    sys.exit(0)

# ---------------------------------------------------------------------------
# Interactive shell or single command
# ---------------------------------------------------------------------------

if not extras:
    GCShell(v, cwd=_LAUNCH_CWD).cmdloop()
else:
    # On Windows the shell does not expand wildcards, so we do it here.
    # Only expand arguments that follow the command name (extras[1:]).
    if os.name == 'nt':
        import glob as _glob
        expanded = [extras[0]]
        for arg in extras[1:]:
            if '*' in arg or '?' in arg:
                pat = arg if os.path.isabs(arg) else os.path.join(_LAUNCH_CWD, arg)
                matches = _glob.glob(pat)
                expanded += matches if matches else [arg]
            else:
                expanded.append(arg)
        extras = expanded
    GCShell(v, cwd=_LAUNCH_CWD).onecmd(shlex.join(extras))
