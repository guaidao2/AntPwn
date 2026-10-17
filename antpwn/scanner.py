"""AntPwn vulnerability scanner: rule engine on decompiler output
漏洞扫描: 危险函数规则 + 模式识别 + 参数/缓冲大小关联（定义-使用链简化版）
"""
import re

from .decompiler import Decompiler

DANGER = {
    "gets":   ("bof", 10, ("gets() 无长度限制, 栈溢出", "gets() unbounded, stack overflow")),
    "strcpy": ("bof", 8, ("strcpy() 无边界检查", "strcpy() no bounds check")),
    "strcat": ("bof", 8, ("strcat() 无边界检查", "strcat() no bounds check")),
    "sprintf":("bof", 7, ("sprintf() 可能溢出", "sprintf() may overflow")),
    "scanf":  ("bof", 6, ("scanf() %s 无宽度限制", "scanf() %s without width")),
    "read":   ("bof", 5, ("read() 长度大于缓冲区", "read() length exceeds buffer")),
    "free":   ("heap", 5, ("free() 可能 UAF/double-free", "free() possible UAF/double-free")),
    "malloc": ("heap", 1, ("堆分配点", "heap allocation")),
    # NOTE: printf family is NOT blanket-flagged; rule 4 detects true
    # format-string bugs (first argument is a plain variable)
}

WIN_NAMES = ("win", "backdoor", "getshell", "magic", "secret")
_WIN_RE = re.compile(r"(?:^|_)(?:%s)(?:$|_)" % "|".join(WIN_NAMES))
_LIBC_PREFIXES = ("__libc_", "_IO_", "__GI_", "__isoc99_", "__")


def callee_base(name):
    """normalise libc-internal symbol names: `_IO_gets` -> `gets`"""
    base = name.split("@")[0]
    if "." in base:
        base = base.split(".", 1)[0]
    for pref in _LIBC_PREFIXES:
        if base.startswith(pref) and len(base) > len(pref):
            base = base[len(pref):]
            break
    return base.lstrip("_") or base
SH_STRINGS = ("/bin/sh", "/bin/bash", "/bin/dash", "sh -i")


class Finding:
    def __init__(self, kind, func, addr, detail, score, evidence=""):
        self.kind, self.func, self.addr = kind, func, addr
        self.detail, self.score, self.evidence = detail, score, evidence

    @property
    def text(self):
        from . import i18n
        if isinstance(self.detail, tuple):
            return self.detail[0] if i18n.LANG == "zh" else self.detail[1]
        return str(self.detail)

    def __repr__(self):
        return f"[{self.kind}] {self.func} @ {self.addr:#x} {self.text} (score={self.score})"


class Scanner:
    def __init__(self, elf):
        self.elf = elf
        self.dec = Decompiler(elf)
        self.findings = []
        self.funcs = {}

    def scan(self):
        symbols = self.elf.code_symbols()
        if self.elf.section(".dynamic") is None and len(symbols) > 200:
            # static link pulls in all of libc: keep user functions
            # (main's first-hop callees + suspicious names), not libc internals
            symbols = self._static_user_functions(symbols)
        for sym in symbols:
            if sym.size == 0 and sym.value == 0:
                continue
            pf = self.dec.function(sym)
            if pf:
                self.funcs[sym.name] = pf
                self._scan_func(sym, pf)
        self._scan_strings()
        self._scan_symbols()
        self._scan_backdoor_callsites()
        self._scan_indirect_bof()
        self._scan_heap_overflow()
        self.reachable = self._compute_reachable()
        findings = self._dedupe(self.findings)

        def rank(f):
            # user-reachable code first, then higher score
            known = f.func in self.reachable
            return (0 if (not self.reachable or known) else 1, -f.score,
                    f.addr)

        return sorted(findings, key=rank)

    def _static_user_functions(self, symbols):
        from .disasm import Disasm
        ordered = sorted(symbols, key=lambda s: s.value)

        def nearest(addr):
            best = None
            for s in ordered:
                if s.value <= addr:
                    best = s
                else:
                    break
            return best

        keep, frontier = {}, []
        for name in ("main", "_start"):
            sym = self.elf.sym(name)
            if sym and sym.value:
                frontier.append((sym, 0))
        while frontier:
            sym, depth = frontier.pop()
            if not sym or not sym.value or sym.value in keep:
                continue
            keep[sym.value] = sym
            if depth >= 1:
                continue
            code = self.elf.read(sym.value, sym.size or 0x200)
            if not code:
                continue
            try:
                insns = Disasm(code, sym.value, self.elf.bits).linear(len(code))
            except Exception:
                continue
            for ins in insns:
                if ins.is_call and ins.target():
                    tgt = nearest(ins.target())
                    if tgt and tgt.value != sym.value:
                        frontier.append((tgt, depth + 1))
        for s in ordered:
            if _WIN_RE.search(s.name.lower()):
                keep.setdefault(s.value, s)
        return [keep[a] for a in sorted(keep)]

    def _compute_reachable(self):
        """BFS over the recovered call graph from main / _start / entry."""
        seeds = [n for n in ("main", "_start") if n in self.funcs]
        if not seeds and self.funcs:
            entry = getattr(self.elf, "entry", 0) or 0
            best = min(self.funcs, key=lambda n: abs(self.funcs[n].addr - entry))
            seeds = [best]
        seen, queue = set(), list(seeds)
        while queue:
            name = queue.pop()
            if name in seen or name not in self.funcs:
                continue
            seen.add(name)
            for callee in self.funcs[name].calls:
                base = callee.split("@")[0]
                if base in self.funcs and base not in seen:
                    queue.append(base)
        return seen

    @staticmethod
    def _dedupe(findings):
        """one finding per (kind, function, address); keep the highest score"""
        out, seen = [], set()
        for f in findings:
            key = (f.kind, f.func, f.addr)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _scan_func(self, sym, pf):
        # 1) dangerous callee functions
        for c in pf.calls:
            cname = callee_base(c)
            if cname in DANGER:
                kind, score, msg = DANGER[cname]
                self.findings.append(Finding(kind, sym.name, sym.value, msg, score, f"call {cname}()"))
        # 2) backdoor: calls system/execve with /bin/sh string
        for eff in pf.effects:
            if eff[0] == "backdoor_shell":
                cmd = eff[1]
                shell = cmd in ("/bin/sh", "/bin/bash", "sh", "sh -i")
                self.findings.append(Finding(
                    "backdoor", sym.name, sym.value,
                    ("后门函数: 直接 getshell" if shell
                     else f"后门函数: 执行命令 {cmd!r}",
                     "backdoor: spawns a shell directly" if shell
                     else f"backdoor: runs command {cmd!r}"),
                    10 if shell else 9, f"system({cmd!r})"))
        # 3) free without pointer clear (heuristic via pseudo lines)
        frees = [l for l in pf.lines
                 if l[1].split("(")[0] in ("free", "free@plt")]
        if frees and "NULL" not in "".join(l[1] for l in pf.lines) \
                and "= 0" not in "".join(l[1] for l in pf.lines):
            for l in frees:
                self.findings.append(Finding("heap", sym.name, sym.value,
                                             ("free() 后指针未置空 -> UAF 风险",
                                              "free() without NULLing the pointer -> UAF risk"), 8, l[1]))
        # 4) printf(buf) direct — format string when arg is a plain variable
        for l in pf.lines:
            t = l[1]
            callee = t.split("(")[0]
            if callee not in ("printf", "printf@plt", "fprintf", "fprintf@plt",
                              "dprintf", "dprintf@plt", "sprintf", "sprintf@plt"):
                continue
            argpart = t[t.find("(") + 1:t.rfind(")")]
            # first arg must be a variable, not a string literal or format
            first = argpart.split(",")[0].strip()
            if first and not first.startswith('"') and not first[0].isdigit() \
                    and not first.startswith("0x") and "rip" not in first:
                self.findings.append(Finding("fmt", sym.name, sym.value,
                                             ("printf(变量) 无格式化参数",
                                              "printf(variable) with no format string"), 9, t))
        # 5) read into rbp-relative buffer followed by large length (already via DANGER)
        self._dataflow(sym, pf)

    @staticmethod
    def _parse_int(text):
        try:
            t = text.strip().rstrip(",;)")
            return int(t, 0)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_call(line):
        """line like `read@plt(0, v0, 0x200);` -> (base, [args])"""
        if "(" not in line or ")" not in line:
            return None, []
        head = line[:line.find("(")].strip().split()
        if not head:
            return None, []
        base = head[-1].split("@")[0]
        inside = line[line.find("(") + 1:line.rfind(")")]
        args = [a.strip() for a in inside.split(",")]
        return base, args

    def _dataflow(self, sym, pf):
        """Correlate buffer sizes with the lengths passed to input functions.

        Simplified def-use: stack buffers are declared in the pseudo-code
        (`char v0[64];`), so the call arguments can be checked against them
        without a full dataflow engine. Refines/removes the generic DANGER
        findings from step 1.
        """
        # rendered text includes the stack-variable declarations, which the
        # raw pf.lines do not carry
        lines = self.dec.render(pf).splitlines()
        sizes = {}
        for line in lines:
            m = re.search(r"char\s+(v\d+)\[(\d+|0x[0-9a-fA-F]+)\]", line)
            if m:
                sizes[m.group(1)] = int(m.group(2), 0)

        def drop(evidence):
            self.findings = [f for f in self.findings
                             if not (f.func == sym.name and f.evidence == evidence)]

        def add(kind, score, zh, en, evidence):
            drop(evidence)
            self.findings.append(Finding(kind, sym.name, sym.value, (zh, en), score, evidence))

        for line in lines:
            base, args = self._parse_call(line)
            if not base:
                continue
            if base == "read" and len(args) >= 3:
                buf = args[1]
                n = self._parse_int(args[2])
                size = sizes.get(buf)
                if not (size and n):
                    continue
                ev = f"call {base}()"
                if n > size:
                    over = n - size
                    if n == size + 1:
                        add("bof", 9,
                            f"off-by-one: read() 读 {n} 字节到 {buf}[{size}]（写入越界 1 字节）",
                            f"off-by-one: read() writes {n} bytes into {buf}[{size}] (1 byte past)",
                            ev)
                    else:
                        add("bof", 10,
                            f"read() 读 {n} 字节到 {buf}[{size}]，确定溢出 {over} 字节",
                            f"read() writes {n} bytes into {buf}[{size}] -> {over} bytes overflow",
                            ev)
                else:
                    drop(ev)      # bounded read into a big enough buffer: no bug
            elif base in ("gets", "strcpy", "strcat", "sprintf") and len(args) >= 2:
                buf = args[1] if base != "gets" else args[0]
                size = sizes.get(buf)
                if size:
                    dst = ("sprintf" and args[1]) or buf
                    sz = sizes.get(dst, size)
                    add("bof", 10 if base == "gets" else 8,
                        f"{base}() 写入无长度限制，目标 {dst}[{sz}]（缓冲 {sz} 字节）",
                        f"{base}() unbounded write into {dst}[{sz}]",
                        f"call {base}()")
            elif base == "scanf" and len(args) >= 2:
                fmt = args[0].strip('"')
                buf = args[1]
                size = sizes.get(buf)
                if "%s" not in fmt or not size:
                    continue
                width = re.search(r"%(\d+)s", fmt)
                ev = f"call {base}()"
                if width and int(width.group(1)) <= size:
                    drop(ev)      # scanf("%63s", buf[64]) is bounded
                elif not width:
                    add("bof", 8,
                        f'scanf("{fmt}", {buf}) 的 %s 无宽度限制，目标 {buf}[{size}]',
                        f'scanf %s has no width limit, target {buf}[{size}]',
                        ev)

    _SHELL_CMD_RE = re.compile(r"(/bin/sh|/bin/bash|^sh$|^cat\s|^id$|/flag|flag\.txt)")

    def _scan_backdoor_callsites(self):
        """code-pattern backdoor: string load + `mov edi/rdi, ...` + call
        system/execve — the classic obfuscated ret2text win address is the
        argument setup itself (`lea rax, "cat flag"; mov rdi, rax; call system`)"""
        from .disasm import Disasm
        names = {s.value: s.name for s in self.elf.functions()}
        self._plt = self.elf.plt_map()
        names.update(self._plt)
        strmap = dict(self.elf.strings(minlen=1))
        for sym in self.elf.code_symbols():
            if sym.name not in self.funcs or not sym.size:
                continue
            code = self.elf.read(sym.value, sym.size)
            if not code:
                continue
            try:
                insns = Disasm(code, sym.value, self.elf.bits).linear(len(code))
            except Exception:
                continue
            # string-loaded register -> (load address, command text)
            loaded = {}
            for idx, ins in enumerate(insns):
                if ins.mnem in ("mov", "lea") and len(ins.ops) >= 2:
                    dst, src = ins.ops[0], ins.ops[1]
                    text, num = self._operand_string(src, strmap)
                    if text and self._SHELL_CMD_RE.search(text):
                        loaded[dst] = (ins.addr, text)
                        continue
                    if dst in ("edi", "rdi"):
                        src_reg = src
                        if src_reg in loaded:
                            addr, cmd = loaded[src_reg]
                            self._emit_callsite(sym, insns, idx, addr, cmd, names)
                elif ins.mnem == "call":
                    # a call clobbers argument registers; forget string loads
                    loaded.clear()
            # a direct `mov rdi, imm; call system` also reaches here via loop above

    def _operand_string(self, op, strmap):
        m = re.search(r"=>\s*(0x[0-9a-f]+)", op)
        if m:
            return strmap.get(int(m.group(1), 16)), int(m.group(1), 16)
        if op.startswith("0x"):
            try:
                num = int(op, 16)
            except ValueError:
                return None, None
            return strmap.get(num), num
        return None, None

    def _emit_callsite(self, sym, insns, idx, start_addr, cmd, names):
        for nxt in insns[idx + 1:idx + 4]:
            if nxt.mnem == "call" and nxt.ops:
                callee = (names.get(nxt.target()) or
                          getattr(self, "_plt", {}).get(nxt.target()) or
                          nxt.ops[0])
                base = callee_base(callee)
                if base in ("system", "execve"):
                    self.findings.append(Finding(
                        "backdoor", sym.name, start_addr,
                        (f"代码模式后门: {base}({cmd!r})",
                         f"code-pattern backdoor: {base}({cmd!r})"),
                        10 if cmd in ("/bin/sh", "/bin/bash", "sh") else 9,
                        f'string {cmd!r}; call {base}'))
                    return
            if nxt.mnem in ("ret", "jmp"):
                return

    
    def _scan_indirect_bof(self):
        """`sink(dst, src)` where dst is a pointer parameter and the caller
        passes a stack buffer: the overflow happens in the *caller*, e.g.
        `copy_user(buf)` -> `strcpy(param, global)`."""
        regs = {"rdi", "edi", "rsi", "esi", "rdx", "edx"}
        sinks = {}
        for name, pf in self.funcs.items():
            ir = getattr(pf, "ir", None)
            if ir is None:
                continue
            param_vars = set()
            calls = []
            for block in ir.blocks.values():
                for st in block.stmts:
                    if st[0] == "store" and st[1][0] == "var" \
                            and st[2][0] == "reg" and st[2][1] in regs:
                        param_vars.add(st[1][1])
                    if st[0] == "call":
                        calls.append(st)
                term = block.term
                if term and len(term) > 1 and isinstance(term[1], tuple):
                    e = term[1]
                    if e[0] == "call":
                        calls.append(("call", e[1], e[2]))
            for c in calls:
                base = callee_base(c[1])
                if base not in ("strcpy", "strcat", "sprintf"):
                    continue
                if not c[2]:
                    continue
                a0 = c[2][0]
                if a0[0] == "var" and a0[1] in param_vars:
                    sinks[name] = base
                elif a0[0] == "reg" and a0[1] in regs:
                    sinks[name] = base
        for caller, pf in self.funcs.items():
            decls = {}
            for d in pf.var_decls:
                m = re.match(r"char (\w+)\[(\d+)\];", d.strip())
                if m:
                    decls[m.group(1)] = int(m.group(2))
            for callee in pf.calls:
                cname = callee.split("@")[0]
                if cname not in sinks:
                    continue
                for line in pf.lines:
                    text = line[1]
                    if (cname + "(") not in text:
                        continue
                    m = re.search(rf"{re.escape(cname)}\((\w+)", text)
                    if not m or m.group(1) not in decls:
                        continue
                    var = m.group(1)
                    size = decls[var]
                    self.findings.append(Finding(
                        "bof", caller, pf.addr,
                        (f"{cname}({var}[{size}]) -> {sinks[cname]} 无界写回调用者栈缓冲区",
                         f"{cname}({var}[{size}]) -> unbounded {sinks[cname]} into the caller's stack buffer"),
                        8, f"{cname}({var}) -> {sinks[cname]}"))
                    break

    @staticmethod
    def _norm_expr(text):
        return re.sub(r"[\s()]", "", text or "")

    @staticmethod
    def _as_int(text):
        try:
            return int(text.strip(), 0)
        except (TypeError, ValueError):
            return None

    def _scan_heap_overflow(self):
        """malloc(N) followed by read/memcpy/strcpy into the same buffer.

        A constant length larger than N is a heap overflow; exactly N+1 is an
        off-by-one. Variable lengths are skipped (cannot be proven statically).
        """
        for name, pf in self.funcs.items():
            allocs = []          # (normalised buffer expr, size text)
            for _, line in pf.lines:
                m = re.match(r"\s*(.+?)\s*=\s*malloc@plt\((.+)\);\s*$", line)
                if m:
                    allocs.append((self._norm_expr(m.group(1)), m.group(2).strip()))
                if not allocs:
                    continue
                for sink, buf_idx, len_idx in (("read@plt", 1, 2),
                                               ("memcpy@plt", 0, 2),
                                               ("strncpy@plt", 0, 2)):
                    m = re.search(rf"{re.escape(sink)}\(([^,]+), ([^,]+), ([^)]+)\);", line)
                    if not m:
                        continue
                    buf = self._norm_expr(m.group(buf_idx + 1))
                    size_txt = m.group(len_idx + 1).strip()
                    for abuf, asz_txt in allocs:
                        if buf != abuf:
                            continue
                        asz = self._as_int(asz_txt)
                        n = self._as_int(size_txt)
                        if asz is not None and n is not None and n > asz:
                            kind = "offbyone" if n == asz + 1 else "heap_overflow"
                            self.findings.append(Finding(
                                kind, name, pf.addr,
                                (f"malloc({asz_txt}) 后 {sink.split('@')[0]}(..., {size_txt}) 越界写堆",
                                 f"{sink.split('@')[0]}(..., {size_txt}) writes past malloc({asz_txt})"),
                                6 if kind == "offbyone" else 8,
                                f"malloc({asz_txt}) -> {sink.split('@')[0]}({size_txt})"))
                        elif asz is not None and sink in ("strncpy@plt",) and n is None:
                            self.findings.append(Finding(
                                "heap_overflow", name, pf.addr,
                                (f"malloc({asz_txt}) 后 strncpy 无明确长度上界",
                                 f"strncpy into malloc({asz_txt}) without a clear bound"),
                                5, f"malloc({asz_txt}) -> strncpy"))
                        break
                # strcpy has no length argument: flag as risky heap write
                m = re.search(r"strcpy@plt\(([^,]+), ", line)
                if m:
                    buf = self._norm_expr(m.group(1))
                    for abuf, asz_txt in allocs:
                        if buf == abuf:
                            self.findings.append(Finding(
                                "heap_overflow", name, pf.addr,
                                (f"strcpy 写入 malloc({asz_txt}) 的堆块, 源串长度不可控",
                                 f"strcpy into a malloc({asz_txt}) chunk with an unbounded source"),
                                5, f"malloc({asz_txt}) -> strcpy"))
                            break

    def _scan_strings(self):
        for va, s in self.elf.strings():
            if any(w in s for w in SH_STRINGS):
                self.findings.append(Finding("sh_string", ".rodata", va,
                                             (f"发现字符串 {s!r}", f"shell string {s!r}"), 3, s))
            if "flag{" in s or "CTF{" in s:
                self.findings.append(Finding("flag", ".rodata", va,
                                             ("疑似 flag", "possible flag"), 9, s))

    def _scan_symbols(self):
        for s in self.elf.functions():
            if _WIN_RE.search(s.name.lower()):
                if not self.elf.sym("_"):
                    self.findings.append(Finding("backdoor", s.name, s.value,
                                                 ("可疑函数名 (win/backdoor)",
                                                  "suspicious function name (win/backdoor)"), 7, s.name))
        # exec stack
        if self.elf.has_execstack:
            self.findings.append(Finding("exec_stack", "PT_GNU_STACK", 0,
                                         ("栈可执行, 可注入 shellcode",
                                          "executable stack, shellcode possible"), 8, "RWX stack"))
        # no canary + writable buffers
        if not self.elf.canary:
            self.findings.append(Finding("no_canary", "*", 0,
                                         ("无 Canary, 栈溢出可直接覆盖返回地址",
                                          "no Canary, overflow reaches the return address"), 5, ""))
        if not self.elf.is_pie:
            self.findings.append(Finding("no_pie", "*", 0,
                                         ("无 PIE, 地址固定可预测",
                                          "no PIE, addresses are static"), 4, ""))

    def summary(self):
        from collections import Counter
        return Counter(f.kind for f in self.findings)
