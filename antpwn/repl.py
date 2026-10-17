"""AntPwn repl: r2/rizin-like interactive browser for disassembly & pseudo-code.

用法 / usage:
    python3 antpwn.py view <binary>
    antpwn> help

零依赖交互层: 复用 ELF / Disasm / Decompiler / GadgetFinder, 支持管道输入,
因此既能在终端里交互, 也能 `printf 'info\nls\ndisas vuln\nquit\n' | antpwn view x`。
"""
import sys

from . import color, i18n
from .decompiler import Decompiler
from .disasm import Disasm
from .gadgets import GadgetFinder


def _zh():
    return i18n.LANG == "zh"


class Repl:
    def __init__(self, elf):
        self.elf = elf
        self.dec = Decompiler(elf)
        self.gadgets = GadgetFinder(elf)
        self.cur = None          # last function/address looked at
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
            "gadgets": self.cmd_gadgets, "rop": self.cmd_gadgets,
            "plt": self.cmd_plt, "imports": self.cmd_plt,
            "sec": self.cmd_sec, "sections": self.cmd_sec,
            "x": self.cmd_hexdump,
            "quit": self.cmd_quit, "q": self.cmd_quit, "exit": self.cmd_quit,
        }

    # ------------------------------------------------------------------
    def run(self):
        print(color.style("AntPwn view", "bold", "bright_cyan")
              + color.dim(" — disassembly / pseudo-code browser"))
        print(color.dim(f"target: {self.elf.path}"))
        if _zh():
            print(color.dim("输入 help 看命令，quit 退出。"))
        else:
            print(color.dim("type 'help' for commands, 'quit' to leave."))
        print()
        while True:
            if self.interactive:
                try:
                    print(color.section("antpwn> "), end="", flush=True)
                except Exception:
                    pass
            line = sys.stdin.readline()
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
        cands = [s for s in self.elf.functions() if t.lower() in s.name.lower()]
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
            ("disas [func|0xaddr] [n]", "反汇编（n 为字节数）/ disassemble", "disas vuln"),
            ("pseudo [func|0xaddr]", "伪代码 / pseudo-code", "pseudo vuln"),
            ("calls [func]", "该函数调用了谁 / callees", "calls vuln"),
            ("strings [minlen]", "字符串 / strings", "strings 6"),
            ("find <text>", "搜函数名与字符串 / search", "find win"),
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
        pat = arg.lower()
        funcs = [s for s in self.elf.functions() if not pat or pat in s.name.lower()]
        funcs.sort(key=lambda s: s.value)
        print(color.section(f"== functions ({len(funcs)}) =="))
        for s in funcs[:200]:
            print(f"  {color.dim(f'{s.value:#010x}')}  {color.style(s.name, 'bright_cyan'):<40}"
                  f" {color.dim(f'size={s.size:#x}') if s.size else ''}")
        if len(funcs) > 200:
            print(color.dim(f"  ... {len(funcs) - 200} more (ls <filter> to narrow)"))
        print()

    def cmd_disas(self, arg=""):
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
        for ins in Disasm(code, addr).linear(len(code)):
            ops = ", ".join(ins.ops)
            print(f"  {color.dim(f'{ins.addr:#010x}')}  {color.dim(ins.raw.hex().ljust(20))}"
                  f" {color.style(ins.mnem, 'yellow')} {ops}")
        print()

    def cmd_pseudo(self, arg=""):
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
        print(color.section(f"== pseudo {sym.name} @ {sym.value:#x} =="))
        for line in self.dec.render(pf).splitlines():
            if line.strip().startswith("// "):
                print(color.dim(line))
            elif "(" in line and "{" in line:
                print(color.style(line, "bold", "bright_cyan"))
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

    def cmd_quit(self, _arg=""):
        print(color.dim("bye"))
        return False
