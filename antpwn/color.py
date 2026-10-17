"""AntPwn color: ANSI terminal styling with automatic degradation.

- Only styles when stdout is a TTY (pipes/files get plain text, so logs and
  regression scripts keep matching).
- Honours NO_COLOR / CLICOLOR=0, and ANTPWN_COLOR=0/1 as an explicit override.
- On Windows enables VT processing on the console; failure means plain text.
- Zero dependencies, same as the rest of AntPwn.
"""
import os
import sys

_RESET = "\x1b[0m"

_CODES = {
    "reset": _RESET,
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "italic": "\x1b[3m",
    "underline": "\x1b[4m",
    "black": "\x1b[30m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
    "bright_red": "\x1b[91m",
    "bright_green": "\x1b[92m",
    "bright_yellow": "\x1b[93m",
    "bright_blue": "\x1b[94m",
    "bright_magenta": "\x1b[95m",
    "bright_cyan": "\x1b[96m",
}

_enabled = None


def _enable_windows_vt():
    """Turn on ANSI escape processing in classic conhost consoles."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(
            handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


def enabled():
    """Whether styling should be emitted (cached)."""
    global _enabled
    if _enabled is not None:
        return _enabled

    force = os.environ.get("ANTPWN_COLOR")
    if force is not None:
        _enabled = force.strip().lower() not in ("", "0", "false", "no", "off")
        return _enabled
    if os.environ.get("NO_COLOR") or os.environ.get("CLICOLOR") == "0":
        _enabled = False
        return _enabled

    try:
        is_tty = sys.stdout is not None and sys.stdout.isatty()
    except Exception:
        is_tty = False
    if not is_tty:
        _enabled = False
        return _enabled
    if os.name == "nt":
        _enabled = _enable_windows_vt()
        return _enabled
    _enabled = True
    return _enabled


def disable():
    global _enabled
    _enabled = False


def style(text, *codes):
    """Wrap `text` in the given ANSI styles (no-op when colors are off)."""
    if not codes or not enabled():
        return str(text)
    prefix = "".join(_CODES[c] for c in codes if c in _CODES)
    if not prefix:
        return str(text)
    return prefix + str(text) + _RESET


def strip(text):
    """Remove ANSI escape sequences (useful for tests / file output)."""
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", str(text))


# ---- semantic helpers -------------------------------------------------
def head(text):
    return style(text, "bold", "bright_cyan")


def section(text):
    return style(text, "bold", "cyan")


def ok(text):
    return style(text, "green")


def good(text):
    return style(text, "bold", "bright_green")


def warn(text):
    return style(text, "yellow")


def err(text):
    return style(text, "bold", "red")


def info(text):
    return style(text, "cyan")


def dim(text):
    return style(text, "dim")


def value_yes(text):
    """A mitigation that is ON: harder target, warm colour."""
    return style(text, "bright_yellow")


def value_no(text):
    """A mitigation that is OFF: easy target, cool colour."""
    return style(text, "bright_green")


# finding kind -> styles (kept in sync with scanner.Finding.kind)
_KIND_STYLE = {
    "bof": ("bold", "bright_red"),
    "backdoor": ("bold", "bright_magenta"),
    "fmt": ("bold", "yellow"),
    "heap": ("bold", "blue"),
    "flag": ("bold", "bright_green"),
    "exec_stack": ("magenta",),
    "sh_string": ("cyan",),
    "no_canary": ("dim",),
    "no_pie": ("dim",),
    "danger": ("yellow",),
}


def kind(name, text=None):
    text = name if text is None else text
    return style(text, *_KIND_STYLE.get(name, ("white",)))


def score(n, text=None):
    text = str(n) if text is None else text
    if n >= 9:
        return style(text, "bold", "bright_red")
    if n >= 7:
        return style(text, "yellow")
    if n >= 5:
        return style(text, "cyan")
    return style(text, "dim")


# state machine states -> styles (kept in sync with fsm.State)
_STATE_STYLE = {
    "recon": ("cyan",),
    "decompile": ("cyan",),
    "scan": ("yellow",),
    "strategy": ("blue",),
    "offset": ("magenta",),
    "build": ("cyan",),
    "test": ("yellow",),
    "verify": ("green",),
    "done": ("bright_green",),
    "failed": ("red",),
    # graph.py colony/tree log tags
    "TREE": ("dim", "cyan"),
    "COLONY": ("dim", "magenta"),
    # fsm.py logs transitions under the localized "state" label
    "state": ("dim",),
    "状态": ("dim",),
}


def state(name, text=None):
    text = name if text is None else text
    return style(text, *_STATE_STYLE.get(name, ()))


def event(ok_flag, text):
    return style(text, "green" if ok_flag else "red")
