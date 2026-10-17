"""AntPwn gdb plugin launcher / loader helper.

Usage:

    antpwn-gdb <binary> [gdb args…]   # launch gdb with the AntPwn plugin loaded
    antpwn-gdb                        # print a ready-to-paste ~/.gdbinit line
    antpwn-gdb --write                # append that line to ~/.gdbinit
    python -m antpwn.gdb_loader

The plugin only needs gdb's own Python interpreter plus the installed package,
so `pip install antpwn` / `pipx install .` is enough.
"""
import os
import sys


def _pkg_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_expr():
    """one-line gdb `python` command that registers the plugin"""
    return ("import sys; sys.path.insert(0, %r); import antpwn.gdbplugin; "
            "antpwn.gdbplugin.register()" % _pkg_dir())


def gdbinit_line():
    return "python " + load_expr()


def _usage():
    print(__doc__.strip())


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "-h" in argv or "--help" in argv:
        _usage()
        return 0
    if "--write" in argv:
        dest = os.path.expanduser("~/.gdbinit")
        try:
            with open(dest, "a", encoding="utf-8") as fp:
                fp.write("\n# AntPwn gdb plugin\n" + gdbinit_line() + "\n")
        except OSError as exc:
            print(f"[-] cannot write {dest}: {exc}", file=sys.stderr)
            return 2
        print("[+] appended to", dest)
        print("    open gdb, then run: antpwn help")
        return 0
    if argv:
        # launch gdb directly, with the plugin pre-registered
        gdb_bin = os.environ.get("ANTPWN_GDB", "gdb")
        cmd = [gdb_bin, "-q", "-ex", "python " + load_expr(), *argv]
        try:
            os.execvp(gdb_bin, cmd)
        except FileNotFoundError:
            print(f"[-] {gdb_bin!r} not found; install gdb or set ANTPWN_GDB",
                  file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"[-] failed to launch {gdb_bin}: {exc}", file=sys.stderr)
            return 2
        return 0
    print("# Add this line to ~/.gdbinit:")
    print(gdbinit_line())
    print()
    print("# Or launch gdb with the plugin preloaded:")
    print("#   antpwn-gdb ./vuln")
    print("# Or per session inside gdb:")
    print("#   (gdb) python import antpwn.gdbplugin; antpwn.gdbplugin.register()")
    print()
    print("# First check: gdb -q -ex 'antpwn help'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
