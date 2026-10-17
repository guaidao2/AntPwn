"""AntPwn repl: r2/rizin-like interactive browser for disassembly & pseudo-code.

用法 / usage:
    python3 antpwn.py view <binary>
    antpwn> help

零依赖交互层: 复用 ELF / Disasm / Decompiler / GadgetFinder, 支持管道输入,
因此既能在终端里交互, 也能 `printf 'info\nls\ndisas vuln\nquit\n' | antpwn view x`。
"""
import sys

from . import color, histedit, i18n
from .decompiler import Decompiler
from .disasm import Disasm
from .gadgets import GadgetFinder
from .scanner import DANGER, Scanner


def _zh():
    return i18n.LANG == "zh"


def _severity_style(score):
    if score >= 9:
        return ("bold", "bright_red")
    if score >= 7:
        return ("yellow",)
    if score >= 5:
        return ("cyan",)
    return ("dim",)


class _Completer:
    """Tab completion: commands on the first word, symbol names for disassembly."""

    FUNC_CMDS = {"disas", "disasm", "pd", "pseudo", "pdc", "calls",
                 "vuln", "bugs", "xrefs", "callers"}

    def __init__(self, repl):
        self.repl = repl

    def _matches(self, text, line):
        parts = line.lstrip().split()
        first = parts[0] if parts else ""
        if len(parts) <= 1 and not line.endswith(" "):
            return [c for c in sorted(self.repl._commands) if c.startswith(text)]
        if first in self.FUNC_CMDS:
            names = sorted(s.name for s in self.repl.elf.code_symbols())
            return [n for n in names if n.startswith(text)]
        return []

    def complete(self, text, state):
        line = histedit.readline.get_line_buffer() if histedit.available() else ""
        matches = self._matches(text, line)
        return matches[state] if state < len(matches) else None


class Repl:
    def __init__(self, elf):
        self.elf = elf
        self.dec = Decompiler(elf)
        self.gadgets = GadgetFinder(elf)
        self.cur = None          # last function/address looked at
        self.findings = None     # scanner results, filled lazily by _ensure_scan()
        self.vuln_ranges = []    # [(start, end, Finding)] for code highlighting
        self.vuln_funcs = {}     # function name -> [Finding]
        self._xrefs = None       # call target addr -> {caller} (lazy)
        self._callers = None     # callee name -> {caller} (lazy)
        self.interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
        self._commands = {
            "help": self.cmd_help, "?": self.cmd_help,
            "info": self.cmd_info, "i": self.cmd_info,
            "ls": self.cmd_ls, "f": self.cmd_ls, "functions": self.cmd_ls,
            "disas": self.cmd_disas, "disasm": self.cmd_disas, "pd": self.cmd_disas,
            "pseudo": self.cmd_pseudo, "pdc": self.cmd_pseudo,
            "calls": self.cmd_calls,
            "strings": self.cmd_strings,
            "find": self.cmd_find, "/": self.cmd_find,
            "vuln": self.cmd_vuln, "bugs": self.cmd_vuln, "check": self.cmd_vuln,
            "findings": self.cmd_vuln,
            "gadgets": self.cmd_gadgets, "rop": self.cmd_gadgets,
            "plt": self.cmd_plt, "imports": self.cmd_plt,
            "sec": self.cmd_sec, "sections": self.cmd_sec,
            "xrefs": self.cmd_xrefs, "callers": self.cmd_xrefs,
            "gadget": self.cmd_gadget, "g": self.cmd_gadget,
            "export": self.cmd_export, "save": self.cmd_export,
            "x": self.cmd_hexdump,
            "quit": self.cmd_quit, "q": self.cmd_quit, "exit": self.cmd_quit,
        }

    # ------------------------------------------------------------------
    def _ensure_scan(self):
        """Run the vulnerability scanner once and build per-instruction markers."""
        if self.findings is not None:
            return
        self.findings = Scanner(self.elf).scan()
        for f in self.findings:
            sym = None
            if f.func and f.func not in ("*", ".rodata") and not f.func.startswith("."):
                sym = self.elf.sym(f.func)
            if sym is not None and sym.value:
                start = sym.value
                end = start + (sym.size or 0x100)
                self.vuln_ranges.append((start, end, f))
                self.vuln_funcs.setdefault(f.func, []).append(f)

    def _callee_name(self, addr):
        """symbol name of a call target (falls back to the PLT map)"""
        sym = self.elf.sym_at(addr)
        if sym and sym.name:
            return sym.name
        return self.elf.plt_map().get(addr, "")

    def _vuln_hit(self, addr):
        """strongest finding covering this address, or None"""
        best = None
        for start, end, f in self.vuln_ranges:
            if start <= addr < end and (best is None or f.score > best.score):
                best = f
        return best

    # ------------------------------------------------------------------
    def run(self):
        print(color.style("AntPwn view", "bold", "bright_cyan")
              + color.dim(" — disassembly / pseudo-code browser"))
        print(color.dim(f"target: {self.elf.path}"))
        if _zh():
            print(color.dim("输入 help 看命令，quit 退出；vuln 看漏洞，disas/pseudo 自动高亮。"))
        else:
            print(color.dim("type 'help' for commands, 'quit' to leave; "
                            "'vuln' lists bugs, disas/pseudo highlight them."))
        enabled = histedit.setup(_Completer(self).complete)
        if enabled:
            if _zh():
                print(color.dim("readline 已启用：方向键/历史/Tab 补全（历史 ~/.antpwn_history）"))
            else:
                print(color.dim("readline enabled: arrows / history / Tab completion "
                                "(history in ~/.antpwn_history)"))
        print()
        prompt = "antpwn> " if self.interactive else ""
        try:
            while True:
                line = histedit.read_line(prompt)
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                cmd, _, rest = line.partition(" ")
                fn = self._commands.get(cmd.lower())
                if fn is None:
                    print(color.err(f"unknown command: {cmd}") + color.dim(" (help)"))
                    continue
                if fn(rest.strip()) is False:
                    break
        finally:
            histedit.save()

    # ------------------------------------------------------------------
    def _resolve(self, target):
        """name / 0xaddr -> (addr, symbol|None); returns (None, candidates) if ambiguous"""
        if not target:
            return self.cur, None
        t = target.strip()
        if t.lower().startswith("0x"):
            try:
                addr = int(t, 16)
            except ValueError:
                return None, None
            return addr, self.elf.sym_at(addr)
        sym = self.elf.sym(t)
        if sym and sym.value:
            return sym.value, sym
        cands = [s for s in self.elf.code_symbols() if t.lower() in s.name.lower()]
        if len(cands) == 1:
            return cands[0].value, cands[0]
        return None, cands

    def _show_ambiguous(self, cands, target):
        if not cands:
            print(color.err(f"not found: {target}"))
            return
        print(color.warn(f"{len(cands)} matches for {target!r}:"))
        for s in cands[:30]:
            print(f"  {color.dim(f'{s.value:#010x}')}  {s.name}")

    # ------------------------------------------------------------------
    def cmd_help(self, _arg=""):
        rows = [
            ("info", "保护状态与摘要 / mitigations and summary", "info"),
            ("ls [pat]", "列出函数（可按名字过滤）/ list functions", "ls"),
            ("vuln [kind|func]", "扫描并标记漏洞 / scan & mark vulnerabilities", "vuln"),
            ("disas [func|0xaddr] [n]", "反汇编（n 为字节数，自动高亮漏洞行）/ disassemble", "disas vuln"),
            ("pseudo [func|0xaddr]", "伪代码（自动标出危险调用）/ pseudo-code", "pseudo vuln"),
            ("calls [func]", "该函数调用了谁 / callees", "calls vuln"),
            ("strings [minlen]", "字符串 / strings", "strings 6"),
            ("find <text>", "搜函数名与字符串 / search", "find win"),
            ("xrefs [func]", "谁调用了它 / callers + callees", "xrefs vuln"),
            ("gadget [pattern]", "gadget 搜索，支持自由模式 / gadget search", "gadget \"pop rdi; ret\""),
            ("export <file>", "导出 json/html 结果 / export analysis", "export out.html"),
            ("gadgets", "ROP gadget 摘要 / gadget summary", "gadgets"),
            ("plt", "PLT 导入表 / PLT imports", "plt"),
            ("sec", "节与段 / sections and segments", "sec"),
            ("x <0xaddr> [n]", "十六进制视图 / hexdump", "x 0x401000 64"),
            ("quit", "退出 / quit", "quit"),
        ]
        print(color.section("commands"))
        for cmd, desc, example in rows:
            print(f"  {color.style(cmd, 'bold'):<28} {desc}")
            print(f"  {color.dim('  e.g. ' + example)}")
        print(color.dim("  tip: 漏洞行在 disas/pseudo 里自动标红，vuln 可先看全量报告"))
        print()

    def cmd_info(self, _arg=""):
        elf = self.elf
        print(color.section("== info =="))
        print(f"  {'file':<10}{elf.path}")
        print(f"  {'type':<10}{'PIE' if elf.is_pie else 'EXEC'}  "
              f"{'ELF64' if elf.bits == 64 else 'ELF32'}  x86-64")
        print(f"  {'entry':<10}{color.dim(f'{elf.e_entry:#x}')}")
        print(f"  {'PIE':<10}{color.value_yes(i18n.t('yes')) if elf.is_pie else color.value_no(i18n.t('no'))}")
        print(f"  {'NX':<10}{color.value_yes(i18n.t('yes')) if elf.has_nx else color.value_no(i18n.t('no'))}")
        print(f"  {'Canary':<10}{color.value_yes(i18n.t('yes')) if elf.canary else color.value_no(i18n.t('no'))}")
        print(f"  {'RELRO':<10}{color.warn(elf.relro)}")
        print(f"  {'ExecStack':<10}{color.value_yes(i18n.t('yes')) if elf.has_execstack else color.value_no(i18n.t('no'))}")
        print(f"  {'functions':<10}{len(elf.functions())}  "
              f"{'sections':<10}{len(elf.sections)}  {'strings':<10}{len(elf.strings())}")
        print()

    def cmd_ls(self, arg=""):
        self._ensure_scan()
        pat = arg.lower()
        funcs = [s for s in self.elf.code_symbols() if not pat or pat in s.name.lower()]
        funcs.sort(key=lambda s: s.value)
        print(color.section(f"== functions ({len(funcs)}) =="))
        for s in funcs[:200]:
            hits = self.vuln_funcs.get(s.name, [])
            if hits:
                top = max(hits, key=lambda f: f.score)
                marker = color.style("!", *_severity_style(top.score))
                note = color.dim(f"  [{', '.join(sorted({h.kind for h in hits}))}]")
            else:
                marker = " "
                note = ""
            print(f" {marker} {color.dim(f'{s.value:#010x}')}  "
                  f"{color.style(s.name, 'bright_cyan'):<40}"
                  f" {color.dim(f'size={s.size:#x}') if s.size else ''}{note}")
        if len(funcs) > 200:
            print(color.dim(f"  ... {len(funcs) - 200} more (ls <filter> to narrow)"))
        print()

    def cmd_vuln(self, arg=""):
        self._ensure_scan()
        pat = arg.strip().lower()
        items = [f for f in self.findings
                 if not pat or pat in f.kind.lower() or pat in (f.func or "").lower()]
        print(color.section(f"== vulnerabilities ({len(items)}) =="))
        if not items:
            print(color.dim("  no findings"))
            print()
            return
        for f in items:
            style = _severity_style(f.score)
            addr = f"{f.addr:#x}" if f.addr else "-"
            func = f.func or "-"
            print(f"  {color.style(f'[{f.kind:>10}]', *style)} "
                  f"{color.dim(f'{addr:<12}')} {color.style(f'{func:<22}', 'bright_cyan')} "
                  f"{f.text}  {color.dim(f'score={f.score}')}")
        print(color.dim("  disas <func> / pseudo <func> 会自动标出这些位置"))
        print()

    def cmd_disas(self, arg=""):
        self._ensure_scan()
        parts = arg.split()
        target = parts[0] if parts else None
        addr, sym = self._resolve(target)
        if addr is None:
            if isinstance(sym, list):
                self._show_ambiguous(sym, target)
            else:
                print(color.err("usage: disas [func|0xaddr] [n]"))
            return
        if len(parts) > 1:
            try:
                size = int(parts[1], 0)
            except ValueError:
                size = 0x40
        else:
            size = (sym.size if sym and sym.size else 0x40)
        code = self.elf.read(addr, size)
        if not code:
            print(color.err(f"cannot read code at {addr:#x}"))
            return
        self.cur = addr
        name = sym.name if sym else f"0x{addr:x}"
        print(color.section(f"== disas {name} @ {addr:#x} ({len(code)} bytes) =="))
        hits = self.vuln_funcs.get(name, [])
        if hits:
            top = max(hits, key=lambda f: f.score)
            kinds = ", ".join(sorted({h.kind for h in hits}))
            print(color.style(f"// [VULN] {kinds} (top score {top.score})",
                              *_severity_style(top.score)))
        for ins in Disasm(code, addr).linear(len(code)):
            ops = ", ".join(ins.ops)
            hit = self._vuln_hit(ins.addr)
            body = (f"{color.dim(f'{ins.addr:#010x}')}  "
                    f"{color.dim(ins.raw.hex().ljust(20))} "
                    f"{color.style(ins.mnem, 'yellow')} {ops}")
            if not hit:
                print(f"   {body}")
                continue
            style = _severity_style(hit.score)
            # strongest marker only on the dangerous call itself, light rail elsewhere
            call_hit = False
            if ins.mnem == "call" and hit.evidence and ins.target() is not None:
                callee = self._callee_name(ins.target())
                call_hit = bool(callee) and callee.split("@")[0] in hit.evidence
            if call_hit:
                print(f" {color.style('!', *style)} {body}"
                      f"{color.style(f'  ; {hit.kind} score={hit.score}', *style)}"
                      f"{color.style(f'  <= {hit.evidence}', *style)}")
            else:
                print(f" {color.style('|', *style)} {body}")
        print()

    def cmd_pseudo(self, arg=""):
        self._ensure_scan()
        addr, sym = self._resolve(arg.split()[0] if arg.split() else None)
        if addr is None:
            if isinstance(sym, list):
                self._show_ambiguous(sym, arg)
            else:
                print(color.err("usage: pseudo <func|0xaddr>"))
            return
        if sym is None:
            sym = self.elf.sym_at(addr)
        if sym is None:
            print(color.err("no function symbol at that address (decompiler needs a symbol)"))
            return
        pf = self.dec.function(sym)
        if not pf:
            print(color.err("cannot decompile this function"))
            return
        self.cur = sym.value
        hits = self.vuln_funcs.get(sym.name, [])
        print(color.section(f"== pseudo {sym.name} @ {sym.value:#x} =="))
        if hits:
            top = max(hits, key=lambda f: f.score)
            kinds = ", ".join(sorted({h.kind for h in hits}))
            print(color.style(f"// [VULN] {kinds} (top score {top.score})",
                              *_severity_style(top.score)))
        for line in self.dec.render(pf).splitlines():
            if line.strip().startswith("// "):
                print(color.dim(line))
            elif "(" in line and "{" in line:
                print(color.style(line, "bold", "bright_cyan"))
            else:
                callee = line.split("(")[0].strip().split()[-1] if "(" in line and line.split("(")[0].strip() else ""
                base = callee.split("@")[0]
                if base in DANGER:
                    print(color.style(line, *_severity_style(DANGER[base][1])))
                else:
                    print(line)
        print()

    def cmd_calls(self, arg=""):
        addr, sym = self._resolve(arg.split()[0] if arg.split() else None)
        if addr is None or sym is None:
            print(color.err("usage: calls <func>"))
            return
        pf = self.dec.function(sym)
        if not pf:
            print(color.err("cannot decompile this function"))
            return
        print(color.section(f"== calls in {sym.name} ({len(pf.calls)}) =="))
        for c in pf.calls:
            print(f"  {color.info(c)}")
        print()

    def cmd_strings(self, arg=""):
        minlen = 4
        if arg.split():
            try:
                minlen = int(arg.split()[0])
            except ValueError:
                pass
        strs = self.elf.strings(minlen)
        print(color.section(f"== strings ({len(strs)}, minlen={minlen}) =="))
        for va, s in strs[:200]:
            print(f"  {color.dim(f'{va:#010x}')}  {s[:100]}")
        if len(strs) > 200:
            print(color.dim(f"  ... {len(strs) - 200} more"))
        print()

    def cmd_find(self, arg=""):
        if not arg:
            print(color.err("usage: find <text>"))
            return
        q = arg.lower()
        print(color.section(f"== find {arg!r} =="))
        n = 0
        for s in self.elf.functions():
            if q in s.name.lower():
                print(f"  {color.style('func', 'yellow')}  {s.name} @ {color.dim(f'{s.value:#x}')}")
                n += 1
        for va, s in self.elf.strings():
            if q in s.lower():
                print(f"  {color.style('str', 'cyan')}   {color.dim(f'{va:#010x}')}  {s[:100]}")
                n += 1
                if n > 300:
                    break
        if n == 0:
            print(color.dim("  nothing found"))
        print()

    def cmd_gadgets(self, _arg=""):
        g = self.gadgets.find_all()
        print(color.section("== gadgets =="))
        for name in sorted(g):
            first = g[name][0]
            print(f"  {color.style(name, 'yellow'):<22} {color.dim(f'{first.addr:#010x}')}"
                  f"  {color.dim(f'({len(g[name])} found)')}")
        print()

    def cmd_plt(self, _arg=""):
        pm = self.elf.plt_map()
        print(color.section(f"== PLT ({len(pm)}) =="))
        for addr, name in sorted(pm.items()):
            print(f"  {color.dim(f'{addr:#010x}')}  {color.info(name)}")
        print()

    def cmd_sec(self, _arg=""):
        print(color.section("== sections =="))
        for s in self.elf.sections:
            if not s.name:
                continue
            rwx = ""
            if s.flags & 2:
                rwx += "W"
            if s.flags & 4:
                rwx += "X"
            print(f"  {s.name:<18} {color.dim(f'{s.addr:#010x}')} "
                  f"{color.dim(f'off={s.off:#x}')} size={s.size:#x} {color.warn(rwx) if rwx else ''}")
        print(color.section("== segments =="))
        for p in self.elf.phdrs:
            if p.type != 1:
                continue
            flags = ("R" if p.flags & 4 else "-") + ("W" if p.flags & 2 else "-") + ("X" if p.flags & 1 else "-")
            print(f"  LOAD {color.dim(f'{p.vaddr:#010x}')} size={p.memsz:#x} {color.warn(flags)}")
        print()

    def cmd_hexdump(self, arg=""):
        parts = arg.split()
        if not parts:
            print(color.err("usage: x <0xaddr> [n]"))
            return
        try:
            addr = int(parts[0], 0)
            n = int(parts[1], 0) if len(parts) > 1 else 64
        except ValueError:
            print(color.err("usage: x <0xaddr> [n]"))
            return
        data = self.elf.read(addr, n)
        if not data:
            print(color.err(f"cannot read at {addr:#x}"))
            return
        print(color.section(f"== hexdump {addr:#x} ({len(data)} bytes) =="))
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"  {color.dim(f'{addr + off:#010x}')}  {hexs:<47}  {asc}")
        print()

    def _build_xrefs(self):
        """call graph: target address -> caller function names (lazy)"""
        if self._xrefs is not None:
            return
        self._xrefs = {}
        self._callers = {}
        for sym in self.elf.code_symbols():
            code = self.elf.read(sym.value, sym.size or 0x200)
            if not code:
                continue
            try:
                for ins in Disasm(code, sym.value).linear(len(code)):
                    if not ins.is_call:
                        continue
                    tgt = ins.target()
                    if tgt is None:
                        continue
                    self._xrefs.setdefault(tgt, set()).add(sym.name)
            except Exception:
                continue
        for tgt, callers in self._xrefs.items():
            name = self._callee_name(tgt) or f"sub_{tgt:x}"
            self._callers.setdefault(name, set()).update(callers)

    def cmd_xrefs(self, arg=""):
        self._ensure_scan()
        addr, sym = self._resolve(arg.split()[0] if arg.split() else None)
        if addr is None:
            if isinstance(sym, list):
                self._show_ambiguous(sym, arg)
            else:
                print(color.err("usage: xrefs <func|0xaddr>"))
            return
        self._build_xrefs()
        name = sym.name if sym else f"0x{addr:x}"
        callers = self._callers.get(sym.name, set()) if sym else self._xrefs.get(addr, set())
        print(color.section(f"== xrefs to {name} ({len(callers)} callers) =="))
        if not callers:
            print(color.dim("  no direct callers found"))
        for c in sorted(callers):
            print(f"  {color.dim('<-')} {color.info(c)}")
        if sym:
            pf = self.dec.function(sym)
            if pf and pf.calls:
                print(color.section(f"== calls from {name} ({len(pf.calls)}) =="))
                for c in pf.calls:
                    print(f"  {color.dim('->')} {color.info(c)}")
        print()

    def cmd_gadget(self, arg=""):
        from .gadgets import WANT
        if not arg.strip():
            print(color.section("== gadget names =="))
            for name in sorted(WANT):
                n = len(self.gadgets.find_all().get(name, []))
                print(f"  {color.style(name, 'yellow'):<24} {color.dim(f'{n} found')}")
            print(color.dim('  usage: gadget "pop rdi; ret"  (free-form pattern)'))
            print()
            return
        pattern = arg.strip()
        all_g = self.gadgets.find_all()
        if pattern in all_g:
            print(color.section(f"== gadget {pattern} ({len(all_g[pattern])}) =="))
            for g in all_g[pattern][:200]:
                print(f"  {color.dim(f'{g.addr:#010x}')}  {color.info(g.effect)}")
            print()
            return
        tokens = [t.strip().lower() for t in pattern.split(";") if t.strip()]
        if not tokens:
            print(color.err("usage: gadget <name|\"insn; insn; ...\">"))
            return
        found = []
        for va, code in self.elf.exec_segments():
            try:
                insns = Disasm(code, va).linear(len(code))
            except Exception:
                continue
            for i in range(len(insns) - len(tokens) + 1):
                ok = True
                for j, tok in enumerate(tokens):
                    ins = insns[i + j]
                    text = (ins.mnem + " " + ", ".join(ins.ops)).strip().lower()
                    if not (text == tok or text.startswith(tok)):
                        ok = False
                        break
                if ok:
                    found.append(insns[i].addr)
                    if len(found) >= 200:
                        break
            if len(found) >= 200:
                break
        print(color.section(f"== gadget pattern {pattern!r} ({len(found)}) =="))
        for addr in found:
            code = self.elf.read(addr, 24)
            text = ""
            if code:
                ins = Disasm(code, addr).decode_one(0)
                if ins is not None:
                    text = f"{ins.mnem} {', '.join(ins.ops)}"
            print(f"  {color.dim(f'{addr:#010x}')}  {color.info(text)}")
        print()

    def cmd_export(self, arg=""):
        """export the collected analysis to json or html"""
        import html as _html
        import json
        path = arg.strip()
        if not path:
            print(color.err("usage: export <file.json|file.html>"))
            return
        self._ensure_scan()
        data = {
            "binary": self.elf.path,
            "mitigations": {
                "pie": self.elf.is_pie, "nx": self.elf.has_nx,
                "canary": self.elf.canary, "relro": self.elf.relro,
                "execstack": self.elf.has_execstack,
            },
            "functions": [{"name": s.name, "addr": s.value, "size": s.size}
                          for s in self.elf.code_symbols()],
            "findings": [
                {"kind": f.kind, "func": f.func, "addr": f.addr,
                 "text": f.text, "score": f.score, "evidence": f.evidence}
                for f in self.findings
            ],
        }
        if path.lower().endswith(".json"):
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(data, fp, ensure_ascii=False, indent=1)
            print(color.ok(f"[export] {len(data['findings'])} findings -> {path}"))
            print()
            return
        rows = "".join(
            f"<tr><td>{_html.escape(f['kind'])}</td><td>{_html.escape(str(f['func']))}</td>"
            f"<td>0x{f['addr']:x}</td><td>{_html.escape(str(f['text']))}</td>"
            f"<td>{f['score']}</td></tr>" for f in data["findings"])
        page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                f"<title>AntPwn view - {_html.escape(self.elf.path)}</title>"
                "<style>body{background:#111;color:#ddd;font-family:monospace}"
                "table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8px}"
                "th{color:#8ce8a4}</style></head><body>"
                f"<h1>AntPwn view: {_html.escape(self.elf.path)}</h1>"
                f"<pre>PIE={data['mitigations']['pie']} NX={data['mitigations']['nx']} "
                f"Canary={data['mitigations']['canary']} RELRO={data['mitigations']['relro']}</pre>"
                "<table><tr><th>kind</th><th>func</th><th>addr</th><th>detail</th><th>score</th></tr>"
                f"{rows}</table></body></html>")
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(page)
        print(color.ok(f"[export] {len(data['findings'])} findings -> {path}"))
        print()

    def cmd_quit(self, _arg=""):
        print(color.dim("bye"))
        return False
