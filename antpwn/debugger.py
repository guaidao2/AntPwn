"""AntPwn debugger: native ptrace-based dynamic debugger (ctypes, no gdb)
动态调试器: 断点/单步/寄存器/内存读写, 全部基于 ptrace 系统调用
"""
import ctypes
import os
import signal
import struct

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_EXITKILL = 0x100000

REG_NAMES = ("r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi "
             "orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs").split()


class Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in REG_NAMES]


class ProcessError(RuntimeError):
    pass


class Breakpoint:
    def __init__(self, addr, orig):
        self.addr, self.orig, self.enabled = addr, orig, True


class Process:
    def __init__(self, path, argv=None, envp=None):
        self.path = path
        try:
            with open(path, "rb") as fp:
                head = fp.read(5)
            self.bits = 64 if head[4] == 2 else 32
        except (OSError, IndexError):
            self.bits = 64
        self.arch = "x86_64" if self.bits == 64 else "i386"
        self.argv = [path] + (argv or [])
        self.envp = envp or [f"PATH={os.environ.get('PATH','')}", "HOME=/home/z"]
        self.pid = None
        self.bps = {}
        self.base = 0
        self.stdin_w = None
        self._stdin_pipe = os.pipe()

    def _ptrace(self, req, addr=None, data=None):
        ctypes.set_errno(0)
        rc = libc.ptrace(req, self.pid, addr, data)
        if rc == -1:
            err = ctypes.get_errno()
            hint = ""
            if req in (PTRACE_GETREGS, PTRACE_SETREGS):
                hint = (" (ptrace disabled by the container, or the kernel "
                        "lacks IA32 compat support)" if self.bits == 32 else
                        " (ptrace disabled by the container?)")
            raise ProcessError(f"ptrace({req}) failed: {os.strerror(err)}{hint}")
        return rc

    def _word(self):
        return 4 if self.bits == 32 else 8

    # ---------------- lifecycle ----------------
    def start(self, entry_bp=False, quiet=True):
        r, w = self._stdin_pipe
        pid = os.fork()
        if pid == 0:
            os.close(w)
            os.dup2(r, 0)
            if quiet:
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, 1)
                os.dup2(devnull, 2)
            libc.ptrace(PTRACE_TRACEME, 0, None, None)
            for e in list(os.environ):
                del os.environ[e]
            for kv in self.envp:
                k = kv.split("=", 1)[0]
                os.environ[k] = kv.split("=", 1)[1] if "=" in kv else ""
            os.execv(self.path, self.argv)
        os.close(r)
        self.stdin_w = w
        self.pid = pid
        os.waitpid(pid, 0)  # exec trap
        self._ptrace(PTRACE_SETOPTIONS, None, PTRACE_O_EXITKILL)
        return self

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        os.write(self.stdin_w, data)

    def close_stdin(self):
        """EOF so blocked read() returns 0 instead of hanging"""
        try:
            os.close(self.stdin_w)
        except OSError:
            pass

    def cont(self, timeout=None):
        self._ptrace(PTRACE_CONT)
        return self._wait(timeout)

    def step(self):
        self._ptrace(PTRACE_SINGLESTEP)
        return self._wait(2.0)

    def _wait(self, timeout=None):
        """non-blocking waitpid poll; never hangs on input-blocked children"""
        import time as _t
        deadline = _t.time() + timeout if timeout else None
        while True:
            r = os.waitpid(self.pid, os.WNOHANG)
            if r != (0, 0):
                _, st = r
                if os.WIFEXITED(st):
                    return ("exit", os.WEXITSTATUS(st))
                if os.WIFSIGNALED(st):
                    return ("killed", os.WTERMSIG(st))
                sig = os.WSTOPSIG(st)
                if sig == signal.SIGTRAP:
                    return ("trap", 0)
                return ("stop", sig)
            if deadline and _t.time() > deadline:
                return ("timeout", 0)
            _t.sleep(0.01)

    def kill(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass

    # ---------------- regs/mem ----------------
    def getregs(self):
        r = Regs()
        self._ptrace(PTRACE_GETREGS, None, ctypes.byref(r))
        if self.bits == 32:
            # on a 64-bit kernel the compat task still fills the 64-bit
            # user_regs_struct; expose i386-style names for the callers
            mask = 0xFFFFFFFF
            r.rip &= mask
            r.rsp &= mask
            r.rbp &= mask
            for a in ("rax", "rcx", "rdx", "rbx", "rsi", "rdi"):
                setattr(r, a, getattr(r, a) & mask)
            r.eip, r.esp, r.ebp = r.rip, r.rsp, r.rbp
            r.eax, r.ecx, r.edx, r.ebx = r.rax, r.rcx, r.rdx, r.rbx
            r.esi, r.edi = r.rsi, r.rdi
        return r

    def setregs(self, r):
        if self.bits == 32:
            # a caller may set `rip` directly (e.g. breakpoint restore); trust it
            try:
                if r.rip != r.eip:
                    r.eip = r.rip
            except AttributeError:
                pass
            for src, dst in (("eip", "rip"), ("esp", "rsp"), ("ebp", "rbp"),
                             ("eax", "rax"), ("ebx", "rbx"), ("ecx", "rcx"),
                             ("edx", "rdx"), ("esi", "rsi"), ("edi", "rdi")):
                if hasattr(r, src):
                    setattr(r, dst, getattr(r, src) & 0xFFFFFFFF)
        self._ptrace(PTRACE_SETREGS, None, ctypes.byref(r))

    def peek(self, addr):
        ctypes.set_errno(0)
        v = libc.ptrace(PTRACE_PEEKTEXT, self.pid, ctypes.c_void_p(addr), None)
        if v == -1 and ctypes.get_errno():
            raise OSError(f"peek {addr:#x} failed")
        return v & 0xFFFFFFFFFFFFFFFF

    def poke(self, addr, val):
        return libc.ptrace(PTRACE_POKETEXT, self.pid,
                           ctypes.c_void_p(addr), ctypes.c_void_p(val))

    def read_mem(self, addr, size):
        # PEEKTEXT always returns a host word (8 bytes on x86-64). Align the
        # read so it never straddles a page boundary, then slice what we need.
        out = bytearray()
        cur, remaining = addr, size
        while remaining > 0:
            base = cur & ~7
            word = self.peek(base).to_bytes(8, "little")
            off = cur - base
            take = min(8 - off, remaining)
            out += word[off:off + take]
            cur += take
            remaining -= take
        return bytes(out)

    def write_mem(self, addr, data):
        cur, i = addr, 0
        while i < len(data):
            base = cur & ~7
            off = cur - base
            word = bytearray(self.peek(base).to_bytes(8, "little"))
            take = min(8 - off, len(data) - i)
            word[off:off + take] = data[i:i + take]
            self.poke(base, int.from_bytes(word, "little"))
            cur += take
            i += take

    # ---------------- breakpoints ----------------
    def bp(self, addr):
        orig = self.peek(addr)
        self.bps[addr] = Breakpoint(addr, orig)
        self.poke(addr, (orig & ~0xFF) | 0xCC)
        return self.bps[addr]

    def hit(self, addr):
        """called when SIGTRAP: check bp, restore, step, re-arm"""
        regs = self.getregs()
        if regs.rip - 1 == addr and addr in self.bps:
            b = self.bps[addr]
            self.poke(addr, b.orig)                      # restore
            regs.rip = addr
            if self.bits == 32:
                regs.eip = addr
            self.setregs(regs)
            self._ptrace(PTRACE_SINGLESTEP)
            os.waitpid(self.pid, 0)
            self.poke(addr, (self.peek(addr) & ~0xFF) | 0xCC)  # re-arm
            return True
        return False

    def wait_bp(self, addr, timeout_loops=200000):
        for _ in range(timeout_loops):
            ev = self.cont()
            if ev[0] == "trap" and self.hit(addr):
                return True
            if ev[0] in ("exit", "killed"):
                return False
        return False

    def mmap_base(self):
        """find libc base via /proc/pid/maps"""
        try:
            with open(f"/proc/{self.pid}/maps") as f:
                for line in f:
                    if "libc.so" in line and "r--p" in line:
                        return int(line.split("-")[0], 16)
        except FileNotFoundError:
            pass
        return 0

    def find_libc(self):
        return self.mmap_base()

    def maps(self):
        out = []
        try:
            with open(f"/proc/{self.pid}/maps") as f:
                for line in f:
                    parts = line.split()
                    rng, perms = parts[0], parts[1]
                    lo, hi = [int(x, 16) for x in rng.split("-")]
                    name = parts[5] if len(parts) > 5 else ""
                    out.append((lo, hi, perms, name))
        except FileNotFoundError:
            pass
        return out
