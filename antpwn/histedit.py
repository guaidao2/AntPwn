"""Optional readline integration: line editing, history and tab completion.

Linux/macOS CPython ships the `readline` module, so the interactive surfaces
(`antpwn view` and the `-i` shell) get arrow keys, history and completion for
free. Windows CPython has no readline; this module then becomes a no-op and the
REPL still works, only without editing/history.

History file:
    ANTPWN_HISTORY=/path/to/file   explicit path
    ~/.antpwn_history              default (when $HOME is available)
    ANTPWN_NO_HISTORY=1            disable persistence entirely
"""
import os

try:
    import readline  # noqa: F401  (unavailable on Windows CPython)
except ImportError:
    readline = None

_HISTFILE = None


def available():
    return readline is not None


def _history_path():
    if os.environ.get("ANTPWN_NO_HISTORY"):
        return None
    explicit = os.environ.get("ANTPWN_HISTORY")
    if explicit:
        return os.path.expanduser(explicit)
    home = os.path.expanduser("~")
    if not home or home == "~":
        return None
    return os.path.join(home, ".antpwn_history")


def setup(completer=None, histfile=None):
    """Enable editing/completion/history. Returns True when readline is active."""
    global _HISTFILE
    if readline is None:
        return False
    try:
        readline.parse_and_bind("tab: complete")
        if completer is not None:
            readline.set_completer(completer)
        path = histfile if histfile is not None else _history_path()
        if path:
            try:
                readline.read_history_file(path)
            except OSError:
                pass
            readline.set_history_length(1000)
            _HISTFILE = path
    except Exception:
        return False
    return True


def read_line(prompt=""):
    """Read one line through input(), so readline editing/history actually applies.

    sys.stdin.readline() bypasses readline; input() goes through PyOS_Readline and
    therefore gives arrows/history/completion. Returns "" on EOF.
    """
    try:
        return input(prompt)
    except EOFError:
        return ""


def save():
    """Persist history (silently ignores an unwritable path)."""
    if readline is None or not _HISTFILE:
        return
    try:
        readline.write_history_file(_HISTFILE)
    except OSError:
        pass


def clear_and_reset():
    if readline is not None:
        try:
            readline.clear_history()
        except Exception:
            pass
