"""Print the snippet that loads the AntPwn gdb plugin.

Usage:

    antpwn-gdb                # print a ready-to-paste ~/.gdbinit line
    antpwn-gdb --write        # append it to ~/.gdbinit (prints the path)
    python -m antpwn.gdb_loader

The plugin only needs gdb's own Python interpreter plus the installed package,
so `pip install antpwn` is enough.
"""
import os
import sys


def gdbinit_line():
    pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return ("python import sys; sys.path.insert(0, %r); "
            "import antpwn.gdbplugin; antpwn.gdbplugin.register()" % pkg_dir)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    line = gdbinit_line()
    if "--write" in argv:
        dest = os.path.expanduser("~/.gdbinit")
        with open(dest, "a", encoding="utf-8") as fp:
            fp.write("\n# AntPwn gdb plugin\n" + line + "\n")
        print("[+] appended to", dest)
        return 0
    print("# Add this line to ~/.gdbinit:")
    print(line)
    print()
    print("# Or per session:")
    print("#   (gdb) python import antpwn.gdbplugin; antpwn.gdbplugin.register()")
    print()
    print("# First check: gdb -q -ex 'antpwn help'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
