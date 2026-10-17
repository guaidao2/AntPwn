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
        for sym in self.elf.code_symbols():
            if sym.size == 0 and sym.value == 0:
                continue
            pf = self.dec.function(sym)
            if pf:
                self.funcs[sym.name] = pf
                self._scan_func(sym, pf)
        self._scan_strings()
        self._scan_symbols()
        return sorted(self.findings, key=lambda f: -f.score)

    def _scan_func(self, sym, pf):
        # 1) dangerous callee functions
        for c in pf.calls:
            cname = c.split("@")[0]
            if cname in DANGER:
                kind, score, msg = DANGER[cname]
                self.findings.append(Finding(kind, sym.name, sym.value, msg, score, f"call {cname}()"))
        # 2) backdoor: calls system/execve with /bin/sh string
        for eff in pf.effects:
            if eff[0] == "backdoor_shell":
                self.findings.append(Finding("backdoor", sym.name, sym.value,
                                             ("后门函数: 直接 getshell", "backdoor: spawns a shell directly"),
                                             10, "system(\"/bin/sh\")"))
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
            if any(w in s.name.lower() for w in WIN_NAMES):
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
