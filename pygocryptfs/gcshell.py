# -*- coding: utf-8 -*-
"""
pygocryptfs.gcshell
~~~~~~~~~~~~~~~~~~~
Interactive shell for gocryptfs vaults, modelled after pycryptomator's CMShell.

MIT License – Copyright (c) 2024-26 maxpat78
"""

import cmd
import os
import sys
import traceback
from glob import glob as sysglob
from os.path import basename, isdir

from .gocryptfs import Vault, backupDirIds, fsck

if os.name == 'nt':
    # shlex bans backslashes in pathnames on Windows
    try:
        from .w32lex import split as _split, join as _join_args
    except ImportError:
        from shlex import split as _split, join as _join_args
else:
    from shlex import split as _split, join as _join_args


def _join(*args):
    return os.path.join(*args).replace('\\', '/')


def _perr():
    print(sys.exception() if hasattr(sys, 'exception') else traceback.format_exc().splitlines()[-1])


class _Options:
    """Lightweight option bag."""
    pass


class GCShell(cmd.Cmd):
    """
    Interactive shell giving Unix-like access to a gocryptfs vault.

    Commands mirror those of pycryptomator's CMShell:
      alias, backup, cd, decrypt, encrypt, ln, ls, mkdir, mv, quit, rm
    """

    intro  = 'PyGocryptfs Shell.  Type help or ? to list commands.'
    prompt = 'GCF:> '

    def __init__(self, vault: Vault, cwd: str = None):
        self.vault    = vault
        self.cd       = '/'       # current virtual directory
        self.real_cwd = cwd or os.getcwd()  # real FS working dir for relative dest paths
        super().__init__()

    # ------------------------------------------------------------------
    # cmd.Cmd hooks
    # ------------------------------------------------------------------

    def preloop(self):
        self.prompt = f':{self.cd}$ '

    def postcmd(self, stop, line):
        self.prompt = f':{self.cd}$ '
        return stop

    def precmd(self, line):
        """Expand shell wildcards in command arguments."""
        if not line.strip():
            return line
        try:
            args = _split(line)
        except ValueError:
            return line
        expanded = []
        for arg in args:
            if '?' in arg or '*' in arg:
                if expanded and expanded[0] == 'encrypt':
                    # resolve relative patterns against the launch CWD, not the process CWD
                    if not os.path.isabs(arg):
                        pat = os.path.join(self.real_cwd, arg)
                    else:
                        pat = arg
                    expanded += sysglob(pat)       # glob real FS for encrypt
                else:
                    expanded += self.vault.glob(arg, root_dir=self.cd) or [arg]
            else:
                expanded.append(arg)
        return _join_args(expanded)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _abs(self, path):
        """Resolve *path* relative to the current virtual directory."""
        if not path:
            return self.cd
        if path == '.':
            return self.cd
        if path.startswith('/'):
            result = path
        else:
            result = _join(self.cd, path)
        # normalise (collapse .., .) keeping forward slashes
        result = os.path.normpath(result).replace('\\', '/')
        return result

    def _real(self, path):
        """Resolve a real-FS path, handling both slash styles and relative paths.
        Relative paths are resolved against the directory from which the program
        was launched, not the vault directory."""
        # normalise both slash styles to os.sep
        path = path.replace('/', os.sep).replace('\\', os.sep)
        if not os.path.isabs(path):
            path = os.path.join(self.real_cwd, path)
        return os.path.normpath(path)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def do_quit(self, arg):
        'Quit the PyGocryptfs Shell'
        sys.exit(0)

    do_exit = do_quit   # alias

    # -- alias -----------------------------------------------------------

    def do_alias(self, arg):
        'Show the real pathname of a virtual file or directory.\n  alias <virtual_path> ...'
        args = _split(arg)
        if not args:
            print('use: alias <virtual_path> [...]')
            return
        for a in args:
            try:
                rp = self.vault.alias(self._abs(a))
                print(rp)
            except Exception:
                _perr()

    # -- backup ----------------------------------------------------------

    def do_backup(self, arg):
        'Backup all gocryptfs.diriv files in a ZIP archive.\n  backup <zip_file>'
        args = _split(arg)
        if not args:
            print('use: backup <zip_file>')
            return
        try:
            backupDirIds(self.vault.base, self._real(args[0]))
        except Exception:
            _perr()

    # -- fsck -------------------------------------------------------------

    def do_fsck(self, arg):
        '''Check vault integrity and optionally repair problems.
  fsck [-r] [-f] [-i] [-v] [-c] [virtual_path]

  -r  repair: automatically delete corrupt/orphan items (no prompt)
  -f  same as -r (force)
  -i  interactive: ask before each deletion
  -v  verbose: also show informational items
  -c  check content: authenticate every block (slow, like gocryptfs -fsck -thorough)

  Default (no -c): structural check only – names, headers, diriv files.
  This matches the default behaviour of gocryptfs -fsck.'''
        args          = _split(arg) if arg.strip() else []
        repair        = '-r' in args or '-f' in args
        if repair:
            [args.remove(x) for x in ('-r', '-f') if x in args]
        interactive   = '-i' in args
        if interactive:   args.remove('-i')
        verbose       = '-v' in args
        if verbose:       args.remove('-v')
        check_content = '-c' in args
        if check_content: args.remove('-c')
        vpath         = self._abs(args[0]) if args else '/'
        try:
            fsck(self.vault, virtual_root=vpath,
                 repair=repair, interactive=interactive, verbose=verbose,
                 check_content=check_content)
        except Exception:
            _perr()

    # -- cd --------------------------------------------------------------

    def do_cd(self, arg):
        'Change current virtual directory.\n  cd <directory>'
        args = _split(arg)
        if not args or len(args) > 1:
            print('use: cd <directory>')
            return
        target = self._abs(args[0])
        info   = self.vault.getInfo(target)
        if not info.exists or not info.isDir:
            print(f'{target}: not a directory')
            return
        self.cd = target

    # -- ls --------------------------------------------------------------

    def do_ls(self, arg):
        '''List virtual files and directories.
  ls [-b] [-r] [-s NSDE-!] [<path> ...]

  -b  suppress directory banner
  -r  recursive
  -s  sort: N=name S=size D=date E=extension - =reverse !=toggle'''
        o    = _Options()
        args = _split(arg)

        o.recursive = '-r' in args
        if o.recursive: args.remove('-r')
        o.banner = '-b' not in args
        if not o.banner: args.remove('-b')
        o.sorting = None
        if '-s' in args:
            i = args.index('-s')
            if i + 1 >= len(args):
                print('sorting method not specified')
                return
            o.sorting = args[i + 1]
            for c in o.sorting:
                if c not in 'NSDE-!':
                    print('bad sort specifier:', c)
                    return
            args.pop(i); args.pop(i)   # remove -s AND the specifier

        if args and args[0] == '-h':
            print('use: ls [-b] [-r] [-s NSDE-!] [<path> ...]')
            return
        if not args:
            args = [self.cd]

        try:
            paths = [self._abs(a) for a in args]
            self.vault.ls(paths, o)
        except Exception:
            _perr()

    # -- decrypt ---------------------------------------------------------

    def do_decrypt(self, arg):
        '''Decrypt files or directories from the vault.
  decrypt [-f] [-m] [-F] <virtual_src> [<virtual_src2> ...] <real_dest>
  decrypt <virtual_src> -      (write to stdout)

  -f  force overwrite
  -m  move (remove encrypted source)
  -F  preserve full tree under destination'''
        args    = _split(arg)
        move    = '-m' in args; [args.remove('-m')] if move else None
        force   = '-f' in args; [args.remove('-f')] if force else None
        fulltree= '-F' in args; [args.remove('-F')] if fulltree else None

        if not args or args[0] == '-h' or len(args) < 2:
            print('use: decrypt [-fmF] <virtual_src> [<virtual_src2> ...] <real_dest>')
            return

        raw_dest = args[-1]
        dest = raw_dest if raw_dest == '-' else self._real(raw_dest)
        try:
            for src in args[:-1]:
                vsrc = self._abs(src)
                info = self.vault.getInfo(vsrc)
                if info.isDir:
                    self.vault.decryptDir(vsrc, dest, force, move)
                else:
                    if len(args) > 2:
                        if os.path.exists(dest) and not os.path.isdir(dest):
                            print(f'Destination {dest} exists and is not a directory!')
                            return
                        if fulltree:
                            fdest = os.path.join(dest, vsrc.lstrip('/'))
                        else:
                            fdest = os.path.join(dest, basename(vsrc))
                    else:
                        fdest = dest
                    print(fdest)
                    self.vault.decryptFile(vsrc, fdest, force, move)
                    if raw_dest == '-':
                        print()
        except Exception:
            _perr()

    # -- encrypt ---------------------------------------------------------

    def do_encrypt(self, arg):
        '''Encrypt real files or directories into the vault.
  encrypt [-f] [-m] [-F] <real_src> [<real_src2> ...] <virtual_dest>

  -f  force overwrite
  -m  move (remove plaintext source)
  -F  preserve full tree under destination'''
        args    = _split(arg)
        move    = '-m' in args; [args.remove('-m')] if move else None
        force   = '-f' in args; [args.remove('-f')] if force else None
        fulltree= '-F' in args; [args.remove('-F')] if fulltree else None

        if not args or args[0] == '-h' or len(args) < 2:
            print('use: encrypt [-Ffm] <real_src> [<real_src2> ...] <virtual_dest>')
            return

        vdest_raw = args[-1]
        try:
            for src in args[:-1]:
                src   = self._real(src)
                vdest = self._abs(vdest_raw)
                if isdir(src):
                    self.vault.encryptDir(src, vdest, force, move)
                else:
                    info = self.vault.getInfo(vdest)
                    if len(args) > 2:
                        if info.exists and not info.isDir:
                            print(f'Destination {vdest} exists and is not a directory!')
                            return
                        if not info.exists:
                            info.isDir = True
                    if info.isDir:
                        if fulltree:
                            vdest = _join(vdest, src)
                        else:
                            vdest = _join(vdest, basename(src))
                    print(vdest)
                    self.vault.encryptFile(src, vdest, force, move)
        except Exception:
            _perr()

    # -- mkdir -----------------------------------------------------------

    def do_mkdir(self, arg):
        '''Create one or more virtual directories.
  mkdir [-R] <dir> [<dir2> ...]

  -R  also create real directories (bypass vault)'''
        args  = _split(arg)
        realfs = '-R' in args
        if realfs: args.remove('-R')
        if not args or args[0] == '-h':
            print('use: mkdir [-R] <dir> [...]')
            return
        for d in args:
            try:
                if realfs:
                    os.makedirs(d, exist_ok=True)
                else:
                    self.vault.mkdir(self._abs(d))
            except Exception:
                _perr()

    # -- mv --------------------------------------------------------------

    def do_mv(self, arg):
        '''Move or rename virtual files / directories.
  mv <src> [<src2> ...] <dest>'''
        args = _split(arg)
        if len(args) < 2 or args[0] == '-h':
            print('use: mv <src> [<src2> ...] <dest>')
            return
        vdest = self._abs(args[-1])
        for src in args[:-1]:
            try:
                self.vault.mv(self._abs(src), vdest)
            except Exception:
                _perr()

    # -- rm --------------------------------------------------------------

    def do_rm(self, arg):
        '''Remove virtual files or directories.
  rm [-f] <path> [<path2> ...]

  -f  force: remove non-empty directories recursively'''
        args  = _split(arg)
        force = '-f' in args
        if force: args.remove('-f')
        if not args or args[0] == '-h':
            print('use: rm [-f] <file|dir> [...]')
            return
        for a in args:
            if a == '/':
                print("Won't erase root directory.")
                return
            try:
                vp   = self._abs(a)
                info = self.vault.getInfo(vp)
                if not info.isDir:
                    self.vault.remove(vp)
                elif force:
                    self.vault.rmtree(vp)
                else:
                    self.vault.rmdir(vp)
            except Exception:
                _perr()

    # -- pwd -------------------------------------------------------------

    def do_pwd(self, arg):
        'Print current virtual directory'
        print(self.cd)

    # -- cat -------------------------------------------------------------

    def do_cat(self, arg):
        'Decrypt a file and print its contents to stdout.\n  cat <virtual_file>'
        args = _split(arg)
        if not args:
            print('use: cat <virtual_file>')
            return
        try:
            self.vault.decryptFile(self._abs(args[0]), '-')
        except Exception:
            _perr()
