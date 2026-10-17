"""Load the AntPwn gdb plugin.

Usage (inside gdb):

    (gdb) source /path/to/AntPwn/antpwn-gdb.py
    (gdb) file ./challenges/bin/baby_bof
    (gdb) antpwn help

Or add to ~/.gdbinit:

    python import sys; sys.path.insert(0, "/path/to/AntPwn"); import antpwn.gdbplugin; antpwn.gdbplugin.register()

The plugin only uses gdb's own Python interpreter and AntPwn's standard library
code, so there is nothing extra to install.
"""
import os
import sys

try:
    import gdb  # noqa: F401
except ImportError:
    raise SystemExit("antpwn-gdb.py must be sourced from inside gdb")

try:
    _here = os.path.dirname(os.path.abspath(__file__))
except NameError:               # `source` did not define __file__
    _here = os.getcwd()

if _here and _here not in sys.path:
    sys.path.insert(0, _here)

import antpwn.gdbplugin as _plugin  # noqa: E402

_plugin.register()
