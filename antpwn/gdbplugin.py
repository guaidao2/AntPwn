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

import gdb  # noqa: E402  (only available inside gdb)

from . import color, i18n  # noqa: E402
from .disasm import Disasm  # noqa: E402
from .elf import ELF  # noqa: E402
from .exploits import ExploitContext, all_strategies, cyclic, cyclic_find  # noqa: E402
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

# gdb readline needs \001/\002 around the non-printing escape sequences,
# otherwise cursor positioning breaks on long command lines.
PROMPT_ON = "\001\033[1;36m\002antpwn\001\033[0m\002$ "
PROMPT_OFF = "\001\033[1;33m\002antpwn\001\033[0m\002$ "


def _t(zh, en):
    return zh if i18n.LANG == "zh" else en


class _TraceBreakpoint(gdb.Breakpoint):
    """breakpoint on a dangerous call site, logging args + backtrace"""

    def __init__(self, plugin, label, addr):
        super().__init__(f"*{addr:#x}", internal=True)
        self.plugin = plugin
        self.label = label

    def stop(self):
        try:
            return self.plugin._trace_hit(self.label) == "stop"
        except Exception as exc:                      # never break the session
            gdb.write(f"antpwn trace: {exc!r}\n")
        return False


class _VulnBreakpoint(gdb.Breakpoint):
    """breakpoint planted by `antpwn vuln --bp` on a dangerous call"""

    def __init__(self, plugin, label, addr):
        super().__init__(f"*{addr:#x}", internal=True)
        self.plugin = plugin
        self.label = label

    def stop(self):
        try:
            self.plugin._vuln_bp_hit(self.label)
        except Exception as exc:
            gdb.write(f"antpwn vuln bp: {exc!r}\n")
        return False


class AntPwnCommand(gdb.Command):
    """AntPwn analysis inside gdb: antpwn <recon|vuln|disas|pseudo|xrefs|offset|trace|plan|lang>"""

    def __init__(self):
        # completer_class=-1 tells gdb to call our own complete() method
        super().__init__("antpwn", gdb.COMMAND_USER, completer_class=-1)
        self._repl_cache = {}
        self.prompt_enabled = True
        self.offset = None
        self.caps = set()
        self.trace_bps = []
        self.trace_counts = {}
        self.trace_stop = False
        self.trace_max = 200
        self.trace_dump = False
        self.trace_last = None
        self.trace_repeat = 0
        self.trace_log = []          # [(label, {"args": [...], "bt": [...]})]
        self.vuln_bps = []
        self._ctx_cache = None
        self._last_pid = None

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

    def _inferior_pid(self):
        try:
            return gdb.selected_inferior().pid
        except Exception:
            return 0

    def _shim_ctx(self):
        """ExploitContext for pheromone records / planning (cached per binary)"""
        if self._ctx_cache is not None:
            return self._ctx_cache
        repl = self._repl()
        repl._ensure_scan()
        scanner = Scanner(repl.elf)
        scanner.scan()
        ctx = ExploitContext(repl.elf, scanner, GadgetFinder(repl.elf),
                             Logger(verbose=False))
        if self.offset:
            ctx.offset = self.offset
            ctx.capabilities.add(CAP_RIP)
        if self._libc_base():
            ctx.capabilities.add(CAP_LIBC)
        self._ctx_cache = ctx
        return ctx

    def _set_cvar(self, name, value):
        try:
            if value is None:
                gdb.execute(f"set ${name} = 0")
            else:
                gdb.execute(f"set ${name} = {int(value)}")
        except gdb.error:
            pass

    def _drop_stale_process_caps(self):
        self.caps.discard(CAP_LIBC)
        self.trace_counts = {}
        self.trace_log = []
        self.trace_last = None
        self.trace_repeat = 0

    def _check_new_process(self):
        pid = self._inferior_pid()
        if pid and self._last_pid and pid != self._last_pid:
            self._drop_stale_process_caps()
            self._ctx_cache = None
        self._last_pid = pid

    def _session(self):
        regs = {}
        if self._inferior_pid():
            for name in ("rip", "rsp", "rbp", "rdi", "rsi", "rdx", "rax", "rcx"):
                try:
                    regs[name] = int(gdb.parse_and_eval(f"${name}"))
                except gdb.error:
                    pass
        return {
            "offset": self.offset,
            "libc_base": self._libc_base(),
            "caps": sorted(self.caps),
            "trace": dict(self.trace_counts),
            "trace_log": [
                {"func": label, "detail": info.get("detail"),
                 "args": [f"{v:#x}" for v in info.get("args", [])]}
                for label, info in self.trace_log[:200]
            ],
            "registers": {k: f"{v:#x}" for k, v in regs.items()},
            "pc": f"{self._pc():#x}" if self._pc() else None,
            "gdb": gdb.VERSION,
        }

    def _report_data(self):
        repl = self._repl()
        repl._ensure_scan()
        elf = repl.elf
        functions = [{"name": s.name, "addr": s.value, "calls": []}
                     for s in sorted(elf.code_symbols(), key=lambda s: s.value)[:40]]
        findings = [{"kind": f.kind, "func": f.func, "addr": f.addr,
                     "detail": f.text, "score": f.score} for f in repl.findings]
        session = self._session()
        notes = []
        if session.get("offset"):
            notes.append((f"gdb 现场解得 offset={session['offset']}",
                          f"offset={session['offset']} recovered inside gdb"))
        if session.get("libc_base"):
            notes.append((f"libc base={session['libc_base']:#x}（来自 gdb maps）",
                          f"libc base={session['libc_base']:#x} (from gdb maps)"))
        if session.get("trace"):
            notes.append(("trace 命中: " + ", ".join(
                f"{k}×{v}" for k, v in session["trace"].items()),
                          "trace hits: " + ", ".join(
                              f"{k}×{v}" for k, v in session["trace"].items())))
        return {
            "path": elf.path,
            "mitigations": {"PIE": elf.is_pie, "NX": elf.has_nx,
                            "Canary": elf.canary, "RELRO": elf.relro,
                            "ExecStack": elf.has_execstack},
            "functions": functions,
            "findings": findings,
            "strategies": ["gdb session"],
            "aco": [],
            "notes": notes,
            "result": "gdb session",
            "flag": None,
            "remote": None,
            "pheromone": None,
        }

    def _save_report(self, path):
        from .report import save_report

        class _Shim:
            pass

        shim = _Shim()
        shim.report_data = self._report_data()

        save_report(shim, path)
        return path

    def _bits(self):
        """32 or 64 based on the current inferior architecture"""
        try:
            arch = gdb.selected_frame().architecture().name()
        except Exception:
            arch = ""
        if not arch:
            try:
                arch = gdb.execute("show architecture", to_string=True)
            except Exception:
                arch = ""
        return 32 if ("i386" in arch and "x86-64" not in arch) else 64

    _REG32 = {"rip": "eip", "rsp": "esp", "rbp": "ebp", "rax": "eax",
              "rbx": "ebx", "rcx": "ecx", "rdx": "edx", "rsi": "esi",
              "rdi": "edi"}

    def _reg(self, name):
        if self._bits() == 32:
            name = self._REG32.get(name, name)
        return int(gdb.parse_and_eval(f"${name}"))

    def _sp_name(self):
        return "$esp" if self._bits() == 32 else "$rsp"

    def _maps(self):
        """parsed `info proc mappings`: start/end/offset/perms/path rows"""
        try:
            out = gdb.execute("info proc mappings", to_string=True)
        except gdb.error:
            return []
        rows = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                start, end = int(parts[0], 16), int(parts[1], 16)
            except ValueError:
                continue
            try:
                offset = int(parts[3], 16)
            except (IndexError, ValueError):
                offset = 0
            rest = parts[4:]
            perms = ""
            if rest and len(rest[0]) == 4 and set(rest[0]) <= set("rwxps-"):
                perms = rest.pop(0)
            path = " ".join(rest)
            rows.append({"start": start, "end": end, "offset": offset,
                         "perms": perms, "path": path})
        return rows

    def _map_of(self, addr):
        for row in self._maps():
            if row["start"] <= addr < row["end"]:
                return row
        return None

    def _libc_path(self):
        for row in self._maps():
            path = row["path"]
            if "libc" in path and (".so" in path):
                return path
        return None

    def _libc_base(self):
        rows = [r for r in self._maps()
                if "libc" in r["path"] and (".so" in r["path"])]
        if not rows:
            return None
        bases = [r["start"] - r["offset"] for r in rows]
        return min(bases)

    def _file_base(self):
        """load base of the main executable (0 for ET_EXEC)"""
        elf = self._elf()
        if not elf.is_pie:
            return 0
        path = os.path.realpath(self._binary())
        rows = []
        for row in self._maps():
            rp = os.path.realpath(row["path"]) if row["path"] else ""
            if rp == path:
                rows.append(row)
        if not rows:
            return None
        return min(r["start"] - r["offset"] for r in rows)

    def _to_file(self, addr):
        """runtime address -> file (vaddr) address, or None if unmapped/unreadable"""
        base = self._file_base()
        if base is None:
            return None
        return addr - base

    @staticmethod
    def _nearest_sym(elf, vaddr):
        best = None
        for sym in elf.code_symbols():
            if sym.value <= vaddr and (not sym.size or vaddr < sym.value + sym.size):
                if best is None or sym.value > best.value:
                    best = sym
        return best

    def _eval(self, expr):
        try:
            return int(gdb.parse_and_eval(expr))
        except gdb.error:
            return None

    def _read_mem(self, addr, size):
        try:
            return gdb.selected_inferior().read_memory(addr, size).tobytes()
        except (gdb.error, gdb.MemoryError):
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
            ("where", "崩溃现场上下文：$pc/$rsp/寄存器/backtrace", "antpwn where"),
            ("recon", "保护/入口/摘要 / protections and summary", "antpwn recon"),
            ("vuln [kind|func]", "扫描漏洞并标注 / scan and mark findings", "antpwn vuln"),
            ("disas [func|addr] [n]", "反汇编，无参围绕 $pc / disasm, defaults to $pc", "antpwn disas"),
            ("pseudo [func|addr]", "伪代码，无参取 $pc 所在函数 / pseudo-code", "antpwn pseudo"),
            ("xrefs [func]", "调用关系 / callers + callees", "antpwn xrefs vuln"),
            ("x [addr|$reg] [n]", "读内存（默认 $rsp 64 字节）/ hexdump memory", "antpwn x $rsp"),
            ("leak <addr|$reg>", "地址归属 + 符号偏移 / resolve an address", "antpwn leak $rsp"),
            ("maps", "内存布局（标 $rsp）/ memory layout", "antpwn maps"),
            ("offset [gen|$reg|0x..]", "从崩溃现场反解偏移 / decode offset", "antpwn offset"),
            ("trace ...", "危险调用动态追踪 / dynamic call tracing", "antpwn trace on gets"),
            ("plan", "按已知能力给策略建议 / strategy plan", "antpwn plan"),
            ("export <file>", "导出结果（含 session 段）/ export with session", "antpwn export out.json"),
            ("report [file]", "生成 HTML 会话报告 / HTML session report", "antpwn report"),
            ("reset", "清空会话能力/断点 / reset session state", "antpwn reset"),
            ("prompt on|off", "专属提示符开关 / toggle the antpwn prompt", "antpwn prompt off"),
            ("lang zh|en", "中英文切换 / switch language", "antpwn lang en"),
        ]
        print(color.section("== AntPwn gdb =="))
        for name, desc, example in rows:
            cmd = f"antpwn {name}"
            pad = " " * max(1, 30 - len(cmd))
            print(f"  {color.style(cmd, 'bold')}{pad}{desc}")
        # every view command is usable with the `antpwn` prefix; list them so
        # nobody has to guess what `<view cmd>` means
        print(color.section(_t("== view 命令（antpwn <名字> 直接用）==",
                               "== view commands (use as `antpwn <name>`) ==")))
        from .repl import COMMAND_DOCS
        for name, zh, en in COMMAND_DOCS:
            cmd = f"antpwn {name}"
            pad = " " * max(1, 30 - len(cmd))
            print(f"  {color.style(cmd, 'bold')}{pad}{_t(zh, en)}")
        print(color.dim(_t("别名：ls/f/functions、gadgets/rop、plt/imports、sec/sections、"
                           "find /、export/save、gadget/g、vuln/bugs/check/findings",
                           "aliases: ls/f/functions, gadgets/rop, plt/imports, sec/sections, "
                           "find /, export/save, gadget/g, vuln/bugs/check/findings")))
        print(color.dim(_t("gdb 自带 readline：命令历史、Ctrl-R、Tab 补全都可用",
                           "gdb's readline is in charge: history, Ctrl-R and Tab completion work")))
        print()

    def cmd_recon(self):
        self._repl().cmd_info()

    def _dangerous_call_addr(self, repl, finding):
        """file address of the dangerous call instruction behind a finding"""
        sym = repl.elf.sym(finding.func) if finding.func else None
        if sym is None or not sym.size:
            return None
        code = repl.elf.read(sym.value, sym.size)
        if not code:
            return None
        evidence = finding.evidence or ""
        for ins in Disasm(code, sym.value, repl.elf.bits).linear(len(code)):
            if ins.mnem != "call" or ins.target() is None:
                continue
            callee = repl._callee_name(ins.target())
            if callee and callee.split("@")[0] in evidence:
                return ins.addr
        return None

    def cmd_vuln(self, arg=""):
        bits = arg.split()
        command = " ".join(b for b in bits if not b.startswith("--"))
        if "--bp-off" in bits:
            for bp in self.vuln_bps:
                bp.delete()
            self.vuln_bps = []
            print(color.ok(_t("vuln 断点已清除", "vuln breakpoints cleared")))
            return
        plant = "--bp" in bits
        repl = self._repl()
        repl.cmd_vuln(command)
        repl._ensure_scan()
        base = self._file_base() or 0
        rows = []
        for finding in repl.findings:
            if finding.kind not in ("bof", "fmt", "backdoor", "danger"):
                continue
            if not finding.addr or finding.func in ("*", ".rodata", ""):
                continue
            call_addr = self._dangerous_call_addr(repl, finding)
            if call_addr is None and finding.kind in ("bof", "fmt", "danger"):
                continue
            target = call_addr if call_addr is not None else finding.addr
            rows.append((finding, target + base))
        if rows:
            print(color.dim(_t("  -- 可直接下的断点 --", "  -- paste-ready breakpoints --")))
            for finding, rt in rows:
                print(f"  b *{rt:#x}   {color.dim(f'# {finding.kind} {finding.func}')}")
        if plant and rows:
            planted = 0
            for finding, rt in rows:
                if finding.kind not in ("bof", "fmt", "danger"):
                    continue
                self.vuln_bps.append(
                    _VulnBreakpoint(self, f"{finding.kind}@{finding.func}", rt))
                planted += 1
            print(color.ok(_t(f"已下 {planted} 个断点（antpwn vuln --bp-off 清除）",
                              f"planted {planted} breakpoints (antpwn vuln --bp-off clears)")))
        print()

    def cmd_export(self, arg=""):
        path = arg.strip()
        if not path:
            print(color.err(_t("用法: antpwn export out.json|out.html",
                               "usage: antpwn export out.json|out.html")))
            return
        if path.endswith(".html") or path.endswith(".htm"):
            self._save_report(path)
            print(color.ok(_t(f"[export] 会话报告 -> {path}",
                              f"[export] session report -> {path}")))
            return
        repl = self._repl()
        repl.cmd_export(path)
        try:
            import json
            with open(path, encoding="utf-8") as fp:
                data = json.load(fp)
            data["session"] = self._session()
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(data, fp, ensure_ascii=False, indent=2)
            print(color.dim(_t("  已附加 gdb session 段（offset/libc/trace/寄存器）",
                               "  gdb session section appended (offset/libc/trace/regs)")))
        except Exception as exc:
            print(color.warn(f"session merge skipped: {exc!r}"))

    def cmd_report(self, arg=""):
        path = arg.strip() or "antpwn-report.html"
        self._save_report(path)
        print(color.ok(_t(f"[report] 会话报告 -> {path}", f"[report] session report -> {path}")))

    def cmd_reset(self):
        self.offset = None
        self.caps.clear()
        self._ctx_cache = None
        self._flush_trace_collapse()
        self._trace_off()
        for bp in self.vuln_bps:
            bp.delete()
        self.vuln_bps = []
        self.trace_counts = {}
        self.trace_log = []
        self._set_cvar("antpwn_offset", 0)
        self._set_cvar("antpwn_libc_base", 0)
        print(color.ok(_t("会话能力已重置（offset/libc/trace/断点）",
                          "session state reset (offset/libc/trace/breakpoints)")))
        print()

    def cmd_where(self):
        pc = self._pc()
        if pc is None:
            print(color.err(_t("当前没有运行中的进程（先 run）", "no running inferior (run first)")))
            return
        row = self._map_of(pc)
        print(color.section("== where =="))
        sym_info = ""
        try:
            sym_info = gdb.execute("info symbol $pc", to_string=True).strip()
        except gdb.error:
            sym_info = ""
        print(f"  {color.dim('pc')} {pc:#x}  {color.dim(row['path'] if row else '?')}")
        if sym_info:
            print(f"  {color.dim('sym')} {sym_info}")
        faddr = self._to_file(pc)
        if faddr is not None:
            sym = self._nearest_sym(self._elf(), faddr)
            if sym:
                print(f"  {color.dim('func')} {color.style(sym.name, 'yellow')}"
                      f"+{faddr - sym.value:#x}")
            try:
                sym2 = sym or self._nearest_sym(self._elf(), faddr)
                start = sym2.value if sym2 else max(0, faddr - 0x18)
                end = faddr + 0x20
                code = self._elf().read(start, max(0x40, end - start))
                if code:
                    print(color.dim(f"  -- code around $pc ({faddr:#x}) --"))
                    for ins in Disasm(code, start, self._elf().bits).linear(len(code)):
                        if ins.addr < faddr - 0x18 or ins.addr > faddr + 0x20:
                            continue
                        ops = ", ".join(ins.ops)
                        mark = "=>" if faddr == ins.addr else "  "
                        line = (f"./{color.dim(f'{ins.addr:#010x}')} "
                                f"{color.style(ins.mnem, 'yellow')} {ops}")
                        print(f"  {color.style(mark, 'green')} {line}")
            except Exception:
                pass
        rsp = self._reg("rsp")
        word = 4 if self._bits() == 32 else 8
        data = self._read_mem(rsp, 16 * word)
        if data:
            print(color.dim(f"  -- stack @ {'$esp' if word == 4 else '$rsp'}={rsp:#x} --"))
            for i in range(0, len(data), word):
                val = int.from_bytes(data[i:i + word], "little")
                hint = ""
                if val:
                    if val == self._reg("rbp"):
                        hint = " <- rbp"
                    else:
                        mrow = self._map_of(val)
                        if mrow:
                            hint = " -> " + (mrow["path"] or "anon")
                shown = f"{val:#010x}" if word == 4 else f"{val:#018x}"
                print(f"  {color.dim(f'{rsp + i:#012x}')} {shown}{color.dim(hint)}")
        names = (("eip", "esp", "ebp", "edi", "esi", "edx", "eax", "ecx")
                 if self._bits() == 32 else
                 ("rip", "rsp", "rbp", "rdi", "rsi", "rdx", "rax", "rcx"))
        regs = " ".join(f"{r}={self._reg(r):#x}" for r in names)
        print(color.dim("  " + regs))
        try:
            bt = gdb.execute("bt 6", to_string=True)
            for line in bt.splitlines():
                print(color.dim("  " + line))
        except gdb.error:
            pass
        print()

    def cmd_x(self, arg=""):
        parts = arg.split()
        expr = parts[0] if parts else self._sp_name()
        try:
            n = int(parts[1], 0) if len(parts) > 1 else 64
        except ValueError:
            n = 64
        addr = self._eval(expr)
        if addr is None:
            print(color.err(_t(f"无法求值: {expr}", f"cannot evaluate: {expr}")))
            return
        data = self._read_mem(addr, max(1, n))
        if data is None:
            faddr = self._to_file(addr)
            if faddr is not None:
                data = self._elf().read(faddr, max(1, n))
            if data is None:
                print(color.err(f"cannot read {addr:#x}"))
                return
        print(color.section(f"== x {expr} @ {addr:#x} ({len(data)} bytes) =="))
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {color.dim(f'{addr + i:#012x}')}  {hexs:<47}  {color.dim(text)}")
        print()

    def cmd_leak(self, arg=""):
        expr = arg.strip()
        if not expr:
            print(color.err(_t("用法: antpwn leak <addr|$reg>", "usage: antpwn leak <addr|$reg>")))
            return
        value = self._eval(expr)
        if value is None:
            print(color.err(_t(f"无法求值: {expr}", f"cannot evaluate: {expr}")))
            return
        row = self._map_of(value)
        if not row:
            print(color.warn(_t(f"{value:#x} 不在任何映射里", f"{value:#x} is not mapped")))
            return
        base = row["start"] - row["offset"]
        print(color.section("== leak =="))
        print(f"  {color.dim('addr')} {value:#x}")
        print(f"  {color.dim('map ')} {row['path'] or '[anon]'}  "
              f"{row['start']:#x}-{row['end']:#x} {row['perms']}")
        print(f"  {color.dim('off ')} {row['path'] or 'anon'}+{value - base:#x}")
        libc_path = self._libc_path()
        if libc_path and os.path.realpath(row["path"]) == os.path.realpath(libc_path):
            try:
                libc = ELF(libc_path)
                sym = self._nearest_sym(libc, value - base)
                if sym:
                    print(f"  {color.dim('sym ')} {color.style(sym.name, 'yellow')}"
                          f"+{value - base - sym.value:#x}")
            except Exception:
                pass
        try:
            sym_info = gdb.execute(f"info symbol {value:#x}", to_string=True).strip()
            if sym_info:
                print(f"  {color.dim('gdb ')} {sym_info}")
        except gdb.error:
            pass
        print()

    def cmd_maps(self):
        rows = self._maps()
        if not rows:
            print(color.warn(_t("没有可用的内存映射（先 run）", "no memory mappings (run first)")))
            return
        rsp = self._pc() and self._reg("rsp")
        print(color.section("== mappings =="))
        for row in rows:
            mark = "->" if rsp and row["start"] <= rsp < row["end"] else "  "
            path = row["path"] or "[anon]"
            if rsp and row["start"] <= rsp < row["end"]:
                path += f"   <- $rsp ({rsp:#x})"
            print(f"  {color.style(mark, 'green')} {row['start']:#012x}-{row['end']:#012x} "
                  f"{row['perms']:<5} {path}")
        print()

    def cmd_pseudo(self, arg=""):
        argv = arg.split()
        target = argv[0] if argv else None
        repl = self._repl()
        if target:
            repl.cmd_pseudo(arg)
            return
        pc = self._pc()
        faddr = self._to_file(pc) if pc is not None else None
        sym = self._nearest_sym(repl.elf, faddr) if faddr is not None else None
        if not sym:
            print(color.err(_t("$pc 不在主程序里（指定函数名：antpwn pseudo main）",
                               "$pc is not in the main binary (pass a function: antpwn pseudo main)")))
            return
        repl.cmd_pseudo(sym.name)

    def cmd_xrefs(self, arg=""):
        self._repl().cmd_xrefs(arg)

    def cmd_disas(self, arg=""):
        repl = self._repl()
        repl._ensure_scan()
        parts = arg.split()
        target = parts[0] if parts else "$pc"
        if len(parts) > 1:
            try:
                size = int(parts[1], 0)
            except ValueError:
                size = 0x40
        else:
            size = 0
        pc = self._pc()
        # runtime expression ($pc / $rsp+8) or symbol/address
        runtime = self._eval(target) if target.startswith("$") else None
        file_addr = None
        sym = None
        if runtime is not None:
            file_addr = self._to_file(runtime)
            if file_addr is None:
                print(color.err(_t(f"{target} 不在主程序里，用 `x/10i {target}` 看别的映射",
                                   f"{target} is not in the main binary; use `x/10i {target}`")))
                return
            if size:
                start = file_addr
            else:
                sym = self._nearest_sym(repl.elf, file_addr)
                start = sym.value if sym else max(0, file_addr - 0x10)
                size = (sym.size if sym and sym.size else 0x80)
        else:
            addr, sym = self._resolve(target)
            if addr is None:
                if isinstance(sym, list):
                    repl._show_ambiguous(sym, target)
                else:
                    print(color.err("usage: antpwn disas [func|0xaddr|$pc] [n]"))
                return
            start = addr
            if not size:
                size = sym.size if sym and sym.size else 0x40
            file_addr = addr
        code = repl.elf.read(start, size)
        if not code:
            print(color.err(f"cannot read code at {start:#x}"))
            return
        name = sym.name if sym else (target if runtime is not None else f"0x{start:x}")
        print(color.section(f"== disas {name} @ {start:#x} ({len(code)} bytes) =="))
        hits = repl.vuln_funcs.get(name, [])
        if hits:
            top = max(hits, key=lambda f: f.score)
            kinds = ", ".join(sorted({h.kind for h in hits}))
            print(color.style(f"// [VULN] {kinds} (top score {top.score})",
                              *_sev(top.score)))
        for ins in Disasm(code, start, repl.elf.bits).linear(len(code)):
            ops = ", ".join(ins.ops)
            body = (f"{color.dim(f'{ins.addr:#010x}')}  "
                    f"{color.dim(ins.raw.hex().ljust(20))} "
                    f"{color.style(ins.mnem, 'yellow')} {ops}")
            marker = "  "
            if pc is not None:
                fpc = self._to_file(pc)
                if fpc is not None and ins.addr == fpc:
                    marker = "=>"
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
        text = arg.strip()
        if text.startswith("gen"):
            bits = text.split()
            n = 0x400
            path = os.environ.get(
                "ANTPWN_PATTERN", os.path.join(os.getcwd(), "antpwn_pattern.bin"))
            if len(bits) > 1:
                try:
                    n = int(bits[1], 0)
                except ValueError:
                    pass
            if len(bits) > 2:
                path = bits[2]
            with open(path, "wb") as fp:
                fp.write(cyclic(n) + b"\n")
            print(color.info(_t(f"[+] cyclic 模式已写入 {path}（{n} 字节，pwnlib 兼容）",
                                f"[+] cyclic pattern written to {path} ({n} bytes, pwnlib-compatible)")))
            print(color.dim(_t(f"    用 `run < {path}` 跑，崩溃后 `antpwn offset` 反解",
                               f"    run with `run < {path}`, then `antpwn offset` after the crash")))
            return
        pc = self._pc()
        if pc is None:
            print(color.err(_t("当前没有运行中的进程（先 run / 触发崩溃）",
                               "no running inferior (run the target first)")))
            return
        cands = []
        if text:
            # decode an explicit value: `antpwn offset $rsp`, `antpwn offset 0x6161616a`
            try:
                value = int(gdb.parse_and_eval(text))
            except gdb.error:
                print(color.err(_t(f"无法求值: {text}", f"cannot evaluate: {text}")))
                return
            width = 4 if self._bits() == 32 else 8
            off = cyclic_find(value, width=width)
            if off is None:
                print(color.warn(_t(
                    f"{value:#x} 不在 cyclic 模式里（可能只覆盖了一部分，或用的不是 pwnlib/gef pattern）",
                    f"{value:#x} is not part of the cyclic pattern "
                    f"(partial overwrite, or not a pwnlib/gef pattern)")))
                return
            cands.append((off, text))
        else:
            width = 4 if self._bits() == 32 else 8
            pc_name = "eip" if width == 4 else "rip"
            rip = self._reg("rip")
            rbp = self._reg("rbp")
            off = cyclic_find(rip, width=width)
            if off is not None and off < 0x100000:
                cands.append((off, pc_name))
            off = cyclic_find(rbp, width=width)
            if off is not None and off < 0x100000:
                cands.append((off + width,
                              ("saved return via ebp" if width == 4
                               else "saved rip via rbp")))
            if not cands:
                # no direct hit: look for a cyclic word on the stack. These are
                # often just the payload buffer, so print them only as a fallback.
                try:
                    inf = gdb.selected_inferior()
                    stack = inf.read_memory(self._reg("rsp"), 512).tobytes()
                    for i in range(0, len(stack) - width + 1, width):
                        j = cyclic_find(stack[i:i + width], width=width)
                        if j is not None and j < 0x100000:
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
        self._set_cvar("antpwn_offset", self.offset)
        try:
            from .graph import record_edge
            record_edge(self._shim_ctx(), "dt-offset", True)
        except Exception:
            pass
        print(color.ok(_t(f"已记录 offset = {self.offset}（已写入 $antpwn_offset / 信息素）",
                          f"recorded offset = {self.offset} ($antpwn_offset / pheromone updated)")))
        print()

    def _trace_off(self):
        for bp in self.trace_bps:
            bp.delete()
        self.trace_bps = []

    def _flush_trace_collapse(self):
        if self.trace_repeat and self.trace_last:
            print(color.dim(f"    … {self.trace_last} ×{self.trace_repeat} more (collapsed)"))
        self.trace_repeat = 0
        self.trace_last = None

    def cmd_trace(self, arg=""):
        bits = arg.split()
        mode = bits[0].lower() if bits else "show"
        if mode == "on":
            elf = self._elf()
            if self.trace_bps:
                print(color.warn(_t("trace 已在运行（先 antpwn trace off）",
                                    "trace already running (antpwn trace off first)")))
                return
            names = [b for b in bits[1:] if not b.startswith("--")]
            flags = [b for b in bits[1:] if b.startswith("--")]
            self.trace_stop = "--stop" in flags
            self.trace_dump = "--dump" in flags
            self.trace_max = 200
            for f in flags:
                if f.startswith("--max="):
                    try:
                        self.trace_max = int(f.split("=", 1)[1], 0)
                    except ValueError:
                        pass
            wanted = set(DANGER) | {"puts", "printf", "system", "read", "gets",
                                    "scanf", "strcpy", "strcat", "sprintf",
                                    "memcpy", "strncpy", "fgets"}
            available = {}
            for addr, name in elf.plt_map().items():
                if name not in available:
                    available[name] = addr
            if names:
                missing = [n for n in names if n not in available]
                wanted = {n for n in names if n in available}
                if missing:
                    print(color.warn(_t("没有这些 PLT 符号: " + ", ".join(missing),
                                        "not in PLT: " + ", ".join(missing))))
            targets = {name: addr for name, addr in available.items() if name in wanted}
            if not targets:
                print(color.warn(_t("没有找到目标调用点", "no matching call sites")))
                return
            for name, addr in sorted(targets.items()):
                self.trace_bps.append(_TraceBreakpoint(self, name, addr))
            self.trace_counts = {n: 0 for n in targets}
            self.trace_log = []
            self.trace_last = None
            self.trace_repeat = 0
            extra = []
            if self.trace_stop:
                extra.append(_t("命中即停", "stop on hit"))
            if self.trace_dump:
                extra.append(_t("dump 参数", "dump args"))
            extra.append(f"--max={self.trace_max}")
            print(color.ok(_t(f"trace 已开启（{len(targets)} 个调用点；" + "；".join(extra) + "）",
                              f"trace on ({len(targets)} call sites; " + "; ".join(extra) + ")")))
            print(color.dim("  " + ", ".join(sorted(targets))))
            print()
        elif mode == "off":
            self._flush_trace_collapse()
            self._trace_off()
            print(color.ok(_t("trace 已关闭", "trace off")))
            print()
        elif mode == "bps":
            if not self.trace_bps:
                print(color.dim(_t("trace 还没开启：antpwn trace on",
                                   "trace is off: antpwn trace on")))
                return
            print(color.section(_t("== trace 断点 ==", "== trace breakpoints ==")))
            for bp in self.trace_bps:
                print(f"  {color.style(bp.label, 'yellow'):<12} "
                      f"{color.dim(f'*{int(bp.location) if str(bp.location).isdigit() else bp.location}')}")
            print()
        else:
            if not self.trace_counts:
                print(color.dim(_t("trace 还没开启：antpwn trace on [函数...]",
                                   "trace is off: antpwn trace on [funcs...]")))
                return
            self._flush_trace_collapse()
            print(color.section(_t("== trace 命中统计 ==", "== trace hit counts ==")))
            for name, n in sorted(self.trace_counts.items()):
                print(f"  {color.style(name, 'yellow'):<12} {n}")
            if self.trace_stop:
                print(color.dim("  （--stop：命中时会停在调用点，c 继续）",
                                "  (--stop: stops at call sites, `c` to continue)"))
            print()

    def _overflow_hint(self, label, buf):
        """distance from an input buffer to the saved return address slot"""
        if not buf:
            return ""
        try:
            rbp = self._reg("rbp")
        except gdb.error:
            return ""
        if rbp and 0 < rbp - buf < 0x10000:
            word = 4 if self._bits() == 32 else 8
            saved = rbp + word - buf
            return _t(f"  saved_rip≈{saved} (rbp+{word} - buf)",
                      f"  saved_rip≈{saved} (rbp+{word} - buf)")
        return ""

    def _trace_hit(self, label):
        if self._bits() == 32:
            # cdecl: return address at esp, args at esp+4/8/12
            sp = self._reg("esp")
            raw = self._read_mem(sp + 4, 12)
            import struct as _struct
            vals = list(_struct.unpack("<III", raw)) if raw and len(raw) >= 12 \
                else [0, 0, 0]
            rdi, rsi, rdx = vals
        else:
            rdi = self._reg("rdi")
            rsi = self._reg("rsi")
            rdx = self._reg("rdx")
        buf = 0
        if label == "read":
            buf = rsi
            detail = f"fd={rdi} buf={rsi:#x} n={rdx}" + self._overflow_hint(label, rsi)
        elif label == "gets":
            buf = rdi
            detail = f"buf={rdi:#x}" + self._overflow_hint(label, rdi)
        elif label in ("strcpy", "strcat", "sprintf"):
            buf = rdi
            src = self._read_str(rsi, 24) if self.trace_dump else ""
            detail = f"dst={rdi:#x} src={rsi:#x}" + (f" {src!r}" if src else "") + \
                     self._overflow_hint(label, rdi)
        elif label == "scanf":
            detail = f"fmt={self._read_str(rdi)!r} args..."
        else:
            detail = f"rdi={rdi:#x} rsi={rsi:#x} rdx={rdx:#x}"
        if self._bits() == 32:
            detail += "  (cdecl: args from esp+4/8/12)"
        if self.trace_dump and label in ("read", "gets") and buf:
            data = self._read_mem(buf, 32)
            if data:
                detail += f"  [buf: {data[:32]!r}]"
        self.trace_counts[label] = self.trace_counts.get(label, 0) + 1
        self.trace_log.append((label, {"args": [rdi, rsi, rdx], "buf": buf,
                                       "detail": detail}))
        total = sum(self.trace_counts.values())
        if total >= self.trace_max:
            self._flush_trace_collapse()
            print(color.warn(_t(f"trace 达到上限 {self.trace_max}，已自动关闭",
                                f"trace hit max ({self.trace_max}), turning off")))
            self._trace_off()
            return "stop"
        if label == self.trace_last:
            self.trace_repeat += 1
            return "stop" if self.trace_stop else "continue"
        self._flush_trace_collapse()
        self.trace_last = label
        print(color.style(f"[trace] {label}", "bold", "bright_cyan")
              + f"  {color.dim(detail)}")
        try:
            bt = gdb.execute("bt 4", to_string=True)
            for line in bt.splitlines()[:4]:
                print(color.dim("    " + line))
        except gdb.error:
            pass
        return "stop" if self.trace_stop else "continue"

    def _vuln_bp_hit(self, label):
        rdi = self._reg("rdi")
        rsi = self._reg("rsi")
        rdx = self._reg("rdx")
        print(color.style(f"[vuln-bp] {label}", "bold", "red")
              + f"  {color.dim(f'rdi={rdi:#x} rsi={rsi:#x} rdx={rdx:#x}')}")

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
            self._set_cvar("antpwn_libc_base", libc_base)
            print(color.dim(f"  libc base (from gdb maps) = {libc_base:#x}"))
        else:
            print(color.warn(_t("  未发现 libc 映射（静态链接 / musl？）——"
                                "ret2libc、one_gadget 类路线不可用",
                                "  no libc mapping found (static link / musl?) — "
                                "ret2libc and one_gadget routes are unavailable")))
        if self.offset:
            print(color.dim(f"  offset (from antpwn offset) = {self.offset}"))
        rows = []
        arch_blocked = set()
        for cls in all_strategies():
            try:
                strat = cls(ctx)
                supported = strat.supported()
                if not supported:
                    arch_blocked.add(strat.name)
                ok = supported and bool(strat.feasible())
            except Exception:
                strat, ok = None, False
            if strat is not None:
                rows.append((STRATEGY_PRIORITY.get(strat.name, 9), strat.name, ok))
        rows.sort()
        base = self._file_base() or 0
        win = ctx.backdoor_addr()
        gadgets = {}
        try:
            gadgets = ctx.gadgets.find_all() or {}
        except Exception:
            gadgets = {}
        libc_path = self._libc_path()

        def rt(addr):
            if addr is None:
                return None
            return addr + base

        def next_steps(name):
            steps = []
            if name == "ret2text" and win:
                steps.append(f"b *{rt(win):#x}          # 后门 / win() 运行时地址")
                steps.append(f"x/4i {rt(win):#x}")
            elif name in ("ret2libc", "one_gadget", "ret2csu"):
                steps.append("antpwn trace on puts printf   # 先拿一个 libc 泄漏点")
                steps.append("antpwn leak $rax              # 命中后解析泄露值")
                if libc_path:
                    steps.append(f"one_gadget {libc_path}        # 如有 one_gadget 工具")
            elif name == "ret2dlresolve":
                steps.append("antpwn trace on read          # 确认 read 的 buf/len")
                steps.append("antpwn disas                 # 看当前函数的 plt0 与 gadget")
            elif name == "ret2syscall":
                steps.append('antpwn gadget "syscall"')
                steps.append('antpwn gadget "pop rdi"')
            elif name == "shellcode":
                steps.append("antpwn sec                    # 确认可执行段")
            elif name == "srop":
                steps.append('antpwn gadget "syscall; ret"')
            elif name == "pivot":
                steps.append('antpwn gadget "leave; ret"')
            elif name == "fmt":
                steps.append("antpwn trace on printf        # 看格式串与参数")
                steps.append("antpwn disas                  # 定位 printf 调用点")
            elif name == "heap":
                steps.append("antpwn vuln heap              # 确认 UAF/df 线索")
            elif name == "canary_brute":
                steps.append("antpwn trace on read gets     # 远程 fork 服务才可行")
            elif name == "offbynull":
                steps.append("ANTPWN_OFFBYNULL=1 启动 gdb 后再试")
            if gadgets:
                keys = [k for k in ("pop rdi", "pop rsi", "pop rdx", "ret") if k in gadgets]
                if keys:
                    addrs = ", ".join(
                        f"{k}={rt(gadgets[k][0].addr):#x}" for k in keys[:3])
                    steps.append(f"# gadget: {addrs}")
            return steps

        REASONS = {
            "ret2text": ("缺后门函数或 offset", "needs a backdoor function / offset"),
            "ret2libc": ("需要可泄露的 puts/printf + pop rdi", "needs a puts/printf leak + pop rdi"),
            "one_gadget": ("需要 libc + 本机 one_gadget", "needs libc + local one_gadget"),
            "ret2csu": ("需要 __libc_csu_init + one_gadget", "needs __libc_csu_init + one_gadget"),
            "ret2dlresolve": ("需要 read@plt + pop rdi/rsi/rdx + partial RELRO",
                              "needs read@plt + pop rdi/rsi/rdx + partial RELRO"),
            "ret2syscall": ("需要 pop rax/rdi/rsi/rdx + syscall gadget",
                            "needs pop rax/rdi/rsi/rdx + syscall gadgets"),
            "shellcode": ("需要可执行段（栈/堆可执行）", "needs an executable segment"),
            "srop": ("需要 syscall; ret gadget", "needs a syscall; ret gadget"),
            "pivot": ("需要 leave;ret 或可用栈迁移点", "needs leave;ret / a usable pivot"),
            "fmt": ("需要格式化字符串漏洞 + 可写 GOT", "needs a format-string bug + writable GOT"),
            "heap": ("仅支持 tcache→GOT（UAF/double-free）", "only tcache→GOT (UAF/double-free)"),
            "canary_brute": ("只支持远程 fork 服务", "remote fork servers only"),
            "offbynull": ("需要 off-by-one 检测 + ANTPWN_OFFBYNULL=1",
                          "needs off-by-one + ANTPWN_OFFBYNULL=1"),
        }

        def blocked_reason(name):
            reason = REASONS.get(name, ("条件不满足", "conditions not met"))
            text = _t(reason[0], reason[1])
            missing = []
            if name not in ("fmt", "heap", "ret2text", "offbynull") and not ctx.offset:
                missing.append(_t("offset", "offset"))
            if name in ("ret2libc", "one_gadget", "ret2csu", "srop") and not libc_base and \
                    name != "srop":
                missing.append("libc base")
            if missing:
                text += _t(f"（缺 {', '.join(missing)}）", f" (missing {', '.join(missing)})")
            return text

        print()
        print(color.section(_t("可行路线（按优先级 + 下一步）",
                               "feasible routes (priority + next steps)")))
        feasible = [r for r in rows if r[2]]
        if feasible:
            for prio, name, _ in feasible:
                print(f"  {color.ok('+')} {color.style(name, 'bold')} "
                      f"{color.dim(f'priority={prio}')}")
                for step in next_steps(name):
                    print(f"      {color.dim('$')} {step}")
        else:
            print(color.warn(_t("  当前没有可行策略（用 antpwn vuln 看漏洞，或先跑 antpwn offset）",
                                "  no feasible strategy right now (see antpwn vuln, or run antpwn offset)")))
        blocked = [r for r in rows if not r[2]]
        if blocked:
            print()
            print(color.section(_t("不可行（缺什么）", "blocked (what is missing)")))
            for _, name, _ in blocked:
                reason = (_t("仅 64 位实现（i386 暂不支持）",
                             "64-bit only (not implemented for i386)")
                          if name in arch_blocked else blocked_reason(name))
                print(f"  {color.dim('-')} {color.style(name, 'yellow'):<16} "
                      f"{color.dim(reason)}")
        print()
        print(color.dim(_t("提示：先 antpwn offset / antpwn trace，再 plan，能力会随会话累积",
                           "tip: run antpwn offset / antpwn trace first; capabilities accumulate in the session")))
        print()

    def cmd_prompt(self, arg=""):
        mode = arg.strip().lower()
        if mode == "off":
            self.prompt_enabled = False
            print(color.ok(_t("antpwn 提示符已关闭（恢复 gdb 默认）",
                              "antpwn prompt off (back to the gdb default)")))
        elif mode == "on":
            self.prompt_enabled = True
            print(color.ok(_t("antpwn 提示符已开启", "antpwn prompt on")))
        else:
            print(color.dim(_t("用法: antpwn prompt on|off / usage: antpwn prompt on|off")))
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
        self.dont_repeat()
        self._check_new_process()
        argv = gdb.string_to_argv(arg)
        sub = argv[0].lower() if argv else "help"
        rest = " ".join(argv[1:])
        handlers = {
            "help": lambda: self.cmd_help(),
            "?": lambda: self.cmd_help(),
            "where": lambda: self.cmd_where(),
            "export": lambda: self.cmd_export(rest),
            "report": lambda: self.cmd_report(rest),
            "reset": lambda: self.cmd_reset(),
            "recon": lambda: self.cmd_recon(),
            "info": lambda: self.cmd_recon(),
            "x": lambda: self.cmd_x(rest),
            "leak": lambda: self.cmd_leak(rest),
            "maps": lambda: self.cmd_maps(),
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
            "prompt": lambda: self.cmd_prompt(rest),
        }
        # our output is python prints, not gdb's pager; keep it from pausing
        try:
            old_pagination = gdb.parameter("pagination")
        except Exception:
            old_pagination = None
        if old_pagination:
            gdb.execute("set pagination off", to_string=True)
        try:
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
        finally:
            if old_pagination:
                gdb.execute("set pagination on", to_string=True)

    def complete(self, text, word):
        subs = ["help", "where", "recon", "vuln", "disas", "pseudo", "xrefs",
                "offset", "trace", "plan", "prompt", "lang", "x", "leak",
                "maps", "export", "report", "reset", "ls", "strings", "find",
                "gadget", "plt", "sec"]
        word = word or ""
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


_prev_prompt_hook = None


def _prompt_hook(current_prompt):
    """gdb.prompt_hook: dedicated prompt, chained to whatever was installed
    before us (gef/pwndbg) so `antpwn prompt off` gives it back untouched."""
    if _plugin is None or not _plugin.prompt_enabled:
        if callable(_prev_prompt_hook):
            try:
                return _prev_prompt_hook(current_prompt)
            except Exception:
                return current_prompt
        return current_prompt
    try:
        alive = gdb.selected_inferior().pid != 0
    except Exception:
        alive = False
    return PROMPT_ON if alive else PROMPT_OFF


def register():
    """idempotent registration of the `antpwn` gdb command"""
    global _plugin
    if _plugin is None:
        global _prev_prompt_hook
        _prev_prompt_hook = getattr(gdb, "prompt_hook", None)
        _plugin = AntPwnCommand()
        try:
            gdb.prompt_hook = _prompt_hook
        except Exception:
            pass
        gdb.write(_t("AntPwn gdb 插件已加载：输入 antpwn help 查看命令\n",
                     "AntPwn gdb plugin loaded: type antpwn help\n"))
    return _plugin
