"""AntPwn GDB plugin — use AntPwn's analysis engine from inside gdb.

Load it from gdb:

    (gdb) source /path/to/AntPwn/antpwn-gdb.py
    (gdb) antpwn help

or in ~/.gdbinit:

    python import sys; sys.path.insert(0, "/path/to/AntPwn"); import antpwn.gdbplugin; antpwn.gdbplugin.register()

Design:

- Read-only commands reuse the same engine as `antpwn view` (ELF / disassembler /
  decompiler / scanner), so findings and highlighting in gdb match the CLI.
- `antpwn offset` decodes the cyclic pattern from the current crash site through
  gdb's own registers/memory: no second ptrace debugger is started.
- `antpwn trace` plants breakpoints on dangerous libc call sites (gets/read/
  scanf/strcpy/...) and logs arguments + backtrace, turning the static dataflow
  into real dynamic evidence. Breakpoints auto-continue.
- `antpwn plan` ranks exploitation strategies against the capabilities already
  known in this session (offset from `antpwn offset`, libc base from gdb maps).

License: MIT (same as AntPwn). `import gdb` only works inside gdb, which is why
this module is not imported by the package itself.
"""
import os

# gdb has a real terminal; keep colours unless the user disabled them explicitly
os.environ.setdefault("ANTPWN_COLOR", "1")

import gdb  # noqa: E402  (only available inside gdb)

from . import color, i18n  # noqa: E402
from .disasm import Disasm  # noqa: E402
from .elf import ELF  # noqa: E402
from .exploits import ExploitContext, all_strategies, cyclic  # noqa: E402
from .fsm import Logger  # noqa: E402
from .gadgets import GadgetFinder  # noqa: E402
from .graph import CAP_LIBC, CAP_RIP  # noqa: E402
from .repl import Repl  # noqa: E402
from .scanner import DANGER, Scanner  # noqa: E402

STRATEGY_PRIORITY = {
    "fmt": 0, "heap": 1, "ret2text": 2, "pivot": 3, "srop": 4,
    "ret2libc": 5, "one_gadget": 5, "ret2csu": 6, "ret2dlresolve": 6,
    "ret2syscall": 6, "shellcode": 7, "canary_brute": 8, "offbynull": 9,
}


def _t(zh, en):
    return zh if i18n.LANG == "zh" else en


class _TraceBreakpoint(gdb.Breakpoint):
    """auto-continuing breakpoint on a dangerous call site"""

    def __init__(self, plugin, label, addr):
        super().__init__(f"*{addr:#x}", internal=True)
        self.plugin = plugin
        self.label = label

    def stop(self):
        try:
            self.plugin._trace_hit(self.label)
        except Exception as exc:                      # never break the session
            gdb.write(f"antpwn trace: {exc!r}\n")
        return False


class AntPwnCommand(gdb.Command):
    """AntPwn analysis inside gdb: antpwn <recon|vuln|disas|pseudo|xrefs|offset|trace|plan|lang>"""

    def __init__(self):
        super().__init__("antpwn", gdb.COMMAND_USER, gdb.COMPLETE_NONE)
        self._repl_cache = {}
        self.offset = None
        self.caps = set()
        self.trace_bps = []
        self.trace_counts = {}

    # ---------------- helpers ----------------
    def _binary(self):
        path = gdb.current_progspace().filename
        if path and os.path.exists(path):
            return path
        return None

    def _elf(self):
        path = self._binary()
        if not path:
            raise gdb.GdbError(_t("没有加载可执行文件（先 file <binary>）",
                                  "no executable loaded (use `file <binary>` first)"))
        return ELF(path)

    def _repl(self):
        path = self._binary()
        if not path:
            raise gdb.GdbError(_t("没有加载可执行文件（先 file <binary>）",
                                  "no executable loaded (use `file <binary>` first)"))
        if path not in self._repl_cache:
            self._repl_cache[path] = Repl(ELF(path))
        return self._repl_cache[path]

    def _pc(self):
        try:
            return int(gdb.parse_and_eval("$pc"))
        except gdb.error:
            return None

    def _reg(self, name):
        return int(gdb.parse_and_eval(f"${name}"))

    def _libc_base(self):
        try:
            out = gdb.execute("info proc mappings", to_string=True)
        except gdb.error:
            return None
        for line in out.splitlines():
            if "libc" not in line or "so" not in line:
                continue
            parts = line.split()
            try:
                return int(parts[0], 16)
            except (IndexError, ValueError):
                continue
        return None

    def _resolve(self, target):
        repl = self._repl()
        addr, sym = repl._resolve(target)
        if addr is not None:
            return addr, sym
        if isinstance(sym, list):
            return None, sym
        # fall back to gdb's own symbol table
        try:
            val = gdb.parse_and_eval(target)
            return int(val), None
        except gdb.error:
            return None, None

    # ---------------- sub commands ----------------
    def cmd_help(self):
        rows = [
            ("recon", "保护/入口/摘要 / protections and summary", "antpwn recon"),
            ("vuln [kind|func]", "扫描漏洞并标注 / scan and mark findings", "antpwn vuln"),
            ("disas [func|addr] [n]", "反汇编（漏洞行高亮 + 当前 PC）/ disasm with PC marker", "antpwn disas vuln"),
            ("pseudo [func|addr]", "伪代码 / pseudo-code", "antpwn pseudo vuln"),
            ("xrefs [func]", "调用关系 / callers + callees", "antpwn xrefs vuln"),
            ("offset [gen [n]]", "从崩溃现场反解偏移 / decode offset from crash", "antpwn offset"),
            ("trace on|off|show", "在危险调用点自动断点记录参数 / dynamic call tracing", "antpwn trace on"),
            ("plan", "按当前已知能力给出策略建议 / strategy plan", "antpwn plan"),
            ("lang zh|en", "中英文切换 / switch language", "antpwn lang en"),
            ("<view 命令>", "其余 view 命令（ls/strings/find/gadget/export…）也可直接用", "antpwn ls"),
        ]
        print(color.section("== AntPwn gdb =="))
        for name, desc, example in rows:
            print(f"  {color.style(name, 'bold'):<26} {desc}")
            print(color.dim(f"    {example}"))
        print()

    def cmd_recon(self):
        self._repl().cmd_info()

    def cmd_vuln(self, arg=""):
        self._repl().cmd_vuln(arg)

    def cmd_pseudo(self, arg=""):
        self._repl().cmd_pseudo(arg)

    def cmd_xrefs(self, arg=""):
        self._repl().cmd_xrefs(arg)

    def cmd_disas(self, arg=""):
        repl = self._repl()
        repl._ensure_scan()
        parts = arg.split()
        target = parts[0] if parts else None
        addr, sym = self._resolve(target)
        if addr is None:
            if isinstance(sym, list):
                repl._show_ambiguous(sym, target)
            else:
                print(color.err("usage: antpwn disas [func|0xaddr] [n]"))
            return
        if len(parts) > 1:
            try:
                size = int(parts[1], 0)
            except ValueError:
                size = 0x40
        else:
            size = sym.size if sym and sym.size else 0x40
        code = repl.elf.read(addr, size)
        if not code:
            print(color.err(f"cannot read code at {addr:#x}"))
            return
        name = sym.name if sym else f"0x{addr:x}"
        print(color.section(f"== disas {name} @ {addr:#x} ({len(code)} bytes) =="))
        hits = repl.vuln_funcs.get(name, [])
        if hits:
            top = max(hits, key=lambda f: f.score)
            kinds = ", ".join(sorted({h.kind for h in hits}))
            print(color.style(f"// [VULN] {kinds} (top score {top.score})",
                              *_sev(top.score)))
        pc = self._pc()
        for ins in Disasm(code, addr).linear(len(code)):
            ops = ", ".join(ins.ops)
            body = (f"{color.dim(f'{ins.addr:#010x}')}  "
                    f"{color.dim(ins.raw.hex().ljust(20))} "
                    f"{color.style(ins.mnem, 'yellow')} {ops}")
            marker = "=>" if pc is not None and ins.addr == pc else "  "
            hit = repl._vuln_hit(ins.addr)
            if not hit:
                print(f"{color.style(marker, 'green')}  {body}")
                continue
            style = _sev(hit.score)
            call_hit = False
            if ins.mnem == "call" and hit.evidence and ins.target() is not None:
                callee = repl._callee_name(ins.target())
                call_hit = bool(callee) and callee.split("@")[0] in hit.evidence
            if call_hit:
                print(f"{color.style(marker, 'green')} {color.style('!', *style)} {body}"
                      f"{color.style(f'  ; {hit.kind} score={hit.score}', *style)}")
            else:
                print(f"{color.style(marker, 'green')} {color.style('|', *style)} {body}")
        print()

    def cmd_offset(self, arg=""):
        if arg.strip().startswith("gen"):
            n = 200
            bits = arg.split()
            if len(bits) > 1:
                try:
                    n = int(bits[1], 0)
                except ValueError:
                    pass
            path = "/tmp/antpwn_pattern.bin"
            with open(path, "wb") as fp:
                fp.write(cyclic(n) + b"\n")
            print(color.info(_t(f"[+] cyclic 模式已写入 {path}（{n} 字节）",
                                f"[+] cyclic pattern written to {path} ({n} bytes)")))
            print(color.dim(_t(f"    用 `run < {path}` 跑，崩溃后 `antpwn offset` 反解",
                               f"    run with `run < {path}`, then `antpwn offset` after the crash")))
            return
        pc = self._pc()
        if pc is None:
            print(color.err(_t("当前没有运行中的进程（先 run / 触发崩溃）",
                               "no running inferior (run the target first)")))
            return
        pat = cyclic(700)

        def pat_off(raw):
            b = (raw & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
            i = pat.find(b)
            if i >= 0:
                return i
            j = pat.find(b[:7])
            if j >= 0 and pat.find(b[:7], j + 1) < 0:
                return j
            return None

        cands = []
        rip = self._reg("rip")
        rbp = self._reg("rbp")
        off = pat_off(rip)
        if off is not None and 0 < off < 600:
            cands.append((off, "rip"))
        off = pat_off(rbp)
        if off is not None and 0 < off < 600:
            cands.append((off + 8, "saved rip via rbp"))
        if not cands:
            # no direct hit: look for a cyclic word on the stack. These are
            # often just the payload buffer, so print them only as a fallback.
            try:
                inf = gdb.selected_inferior()
                stack = inf.read_memory(self._reg("rsp"), 256).tobytes()
                for i in range(0, len(stack) - 7, 8):
                    j = pat.find(stack[i:i + 8])
                    if 0 < j < 600:
                        cands.append((j, "stack"))
            except gdb.error:
                pass
        if not cands:
            print(color.warn(_t("没在寄存器/栈上找到 cyclic 模式：先 `antpwn offset gen` 用模式跑一次",
                                "no cyclic pattern in registers/stack: run `antpwn offset gen` first")))
            if pc:
                print(color.dim(f"  rip={pc:#x}"))
            return
        print(color.section(_t("== 偏移取证 ==", "== offset forensics ==")))
        seen = set()
        for off, where in cands:
            if off in seen:
                continue
            seen.add(off)
            print(f"  {color.style(f'offset={off}', 'bold', 'green')}  {color.dim(where)}")
        self.offset = cands[0][0]
        self.caps.add(CAP_RIP)
        print(color.ok(_t(f"已记录 offset = {self.offset}（antpwn plan 会用到）",
                          f"recorded offset = {self.offset} (used by antpwn plan)")))
        print()

    def cmd_trace(self, arg=""):
        mode = arg.strip() or "show"
        if mode == "on":
            elf = self._elf()
            if self.trace_bps:
                print(color.warn(_t("trace 已在运行", "trace already running")))
                return
            wanted = set(DANGER) | {"puts", "printf", "system", "read", "gets",
                                    "scanf", "strcpy", "strcat", "sprintf",
                                    "memcpy", "strncpy", "fgets"}
            targets = {}
            for addr, name in elf.plt_map().items():
                if name in wanted and name not in targets:
                    targets[name] = addr
            if not targets:
                print(color.warn(_t("没有找到 PLT 中的危险调用点", "no dangerous PLT call sites found")))
                return
            for name, addr in sorted(targets.items()):
                self.trace_bps.append(_TraceBreakpoint(self, name, addr))
            self.trace_counts = {n: 0 for n in targets}
            print(color.ok(_t(f"trace 已开启（{len(targets)} 个调用点，命中自动继续）",
                              f"trace on ({len(targets)} call sites, auto-continue)")))
            print(color.dim("  " + ", ".join(sorted(targets))))
            print()
        elif mode == "off":
            for bp in self.trace_bps:
                bp.delete()
            self.trace_bps = []
            print(color.ok(_t("trace 已关闭", "trace off")))
            print()
        else:
            if not self.trace_counts:
                print(color.dim(_t("trace 还没开启：antpwn trace on",
                                   "trace is off: antpwn trace on")))
                return
            print(color.section(_t("== trace 命中统计 ==", "== trace hit counts ==")))
            for name, n in sorted(self.trace_counts.items()):
                print(f"  {color.style(name, 'yellow'):<12} {n}")
            print()

    def _trace_hit(self, label):
        rdi = self._reg("rdi")
        rsi = self._reg("rsi")
        rdx = self._reg("rdx")
        if label in ("read",):
            detail = f"fd={rdi} buf={rsi:#x} n={rdx}"
        elif label == "gets":
            detail = f"buf(rsi)={rdi:#x}"
        elif label in ("strcpy", "strcat", "sprintf"):
            detail = f"dst={rdi:#x} src={rsi:#x}"
        elif label == "scanf":
            fmt = self._read_str(rdi)
            detail = f"fmt={fmt!r} args..."
        else:
            detail = f"rdi={rdi:#x} rsi={rsi:#x} rdx={rdx:#x}"
        print(color.style(f"[trace] {label}", "bold", "bright_cyan")
              + f"  {color.dim(detail)}")
        try:
            bt = gdb.execute("bt 4", to_string=True)
            for line in bt.splitlines()[:4]:
                print(color.dim("    " + line))
        except gdb.error:
            pass
        self.trace_counts[label] = self.trace_counts.get(label, 0) + 1

    def _read_str(self, addr, limit=64):
        try:
            inf = gdb.selected_inferior()
            data = inf.read_memory(addr, limit).tobytes()
            return data.split(b"\x00")[0].decode("utf-8", "replace")
        except gdb.error:
            return "?"

    def cmd_plan(self):
        repl = self._repl()
        repl._ensure_scan()
        elf = repl.elf
        scanner = Scanner(elf)
        scanner.scan()
        log = Logger(verbose=False)
        ctx = ExploitContext(elf, scanner, GadgetFinder(elf), log)
        libc_base = self._libc_base()
        if self.offset:
            ctx.offset = self.offset
            ctx.capabilities.add(CAP_RIP)
        if libc_base:
            ctx.capabilities.add(CAP_LIBC)
            ctx.live["libc_base"] = libc_base
        ctx.capabilities |= self.caps

        print(color.section(_t("== AntPwn 策略规划 ==", "== AntPwn strategy plan ==")))
        held = sorted(ctx.capabilities) or ["-"]
        print(f"  {_t('已知能力', 'held')}: {', '.join(held)}")
        if libc_base:
            print(color.dim(f"  libc base (from gdb maps) = {libc_base:#x}"))
        if self.offset:
            print(color.dim(f"  offset (from antpwn offset) = {self.offset}"))
        rows = []
        for cls in all_strategies():
            try:
                strat = cls(ctx)
                ok = bool(strat.feasible())
            except Exception:
                strat, ok = None, False
            if strat is not None:
                rows.append((STRATEGY_PRIORITY.get(strat.name, 9), strat.name, ok))
        rows.sort()
        print()
        print(color.section(_t("可行路线（按优先级）", "feasible routes (by priority)")))
        feasible = [r for r in rows if r[2]]
        if feasible:
            for prio, name, _ in feasible:
                print(f"  {color.ok('+')} {color.style(name, 'bold'):<16} "
                      f"{color.dim(f'priority={prio}')}")
        else:
            print(color.warn(_t("  当前没有可行策略（用 antpwn vuln 看漏洞，或先跑 antpwn offset）",
                                "  no feasible strategy right now (see antpwn vuln, or run antpwn offset)")))
        blocked = [r for r in rows if not r[2]]
        if blocked:
            print(color.dim("  " + _t("不可行", "blocked") + ": "
                            + ", ".join(n for _, n, _ in blocked)))
        print()
        print(color.dim(_t("提示：先 antpwn offset / antpwn trace，再 plan，能力会随会话累积",
                           "tip: run antpwn offset / antpwn trace first; capabilities accumulate in the session")))
        print()

    def cmd_lang(self, arg=""):
        lang = arg.strip().lower()
        if lang not in ("zh", "en"):
            print(color.err("usage: antpwn lang zh|en"))
            return
        i18n.set_lang(lang)
        print(color.ok(_t("语言已切换为中文", "language switched to English")))

    # ---------------- dispatch ----------------
    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        sub = argv[0].lower() if argv else "help"
        rest = " ".join(argv[1:])
        handlers = {
            "help": lambda: self.cmd_help(),
            "?": lambda: self.cmd_help(),
            "recon": lambda: self.cmd_recon(),
            "info": lambda: self.cmd_recon(),
            "vuln": lambda: self.cmd_vuln(rest),
            "bugs": lambda: self.cmd_vuln(rest),
            "disas": lambda: self.cmd_disas(rest),
            "disasm": lambda: self.cmd_disas(rest),
            "pd": lambda: self.cmd_disas(rest),
            "pseudo": lambda: self.cmd_pseudo(rest),
            "pdc": lambda: self.cmd_pseudo(rest),
            "xrefs": lambda: self.cmd_xrefs(rest),
            "callers": lambda: self.cmd_xrefs(rest),
            "offset": lambda: self.cmd_offset(rest),
            "trace": lambda: self.cmd_trace(rest),
            "plan": lambda: self.cmd_plan(),
            "lang": lambda: self.cmd_lang(rest),
        }
        if sub in handlers:
            handlers[sub]()
            return
        # everything else is a `view` command (ls/strings/find/gadget/export/...)
        repl = self._repl()
        fn = repl._commands.get(sub)
        if fn is None:
            print(color.err(f"unknown antpwn command: {sub}") + color.dim("  (antpwn help)"))
            return
        fn(rest)

    def complete(self, text, word):
        subs = ["help", "recon", "vuln", "disas", "pseudo", "xrefs", "offset",
                "trace", "plan", "lang", "ls", "strings", "find", "gadget",
                "export", "x", "plt", "sec"]
        return [s for s in subs if s.startswith(word)]


def _sev(score):
    if score >= 9:
        return ("bold", "bright_red")
    if score >= 7:
        return ("yellow",)
    if score >= 5:
        return ("cyan",)
    return ("dim",)


_plugin = None


def register():
    """idempotent registration of the `antpwn` gdb command"""
    global _plugin
    if _plugin is None:
        _plugin = AntPwnCommand()
        gdb.write(_t("AntPwn gdb 插件已加载：输入 antpwn help 查看命令\n",
                     "AntPwn gdb plugin loaded: type antpwn help\n"))
    return _plugin
