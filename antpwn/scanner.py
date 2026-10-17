"""AntPwn vulnerability scanner: rule engine on decompiler output
漏洞扫描: 危险函数规则 + 模式识别 + 交叉引用, 定位函数/行/类型
"""
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
        for sym in self.elf.functions():
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
