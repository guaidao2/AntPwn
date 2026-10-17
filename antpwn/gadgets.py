"""AntPwn gadget engine: ROP gadget finder on native disassembly
Gadget 搜索: 原生反汇编 + 尾部字节回扫, 支持 ret/jmp rsp/leave;ret/syscall 等
"""
from .disasm import Disasm


class Gadget:
    __slots__ = ("addr", "insns", "effect")

    def __init__(self, addr, insns, effect):
        self.addr, self.insns, self.effect = addr, insns, effect

    def __repr__(self):
        return f"{self.addr:#x}: {'; '.join(self.insns)}"


WANT = {
    "pop rdi": (b"\x5f\xc3", "pop rdi; ret"),
    "pop rsi": (b"\x5e\xc3", "pop rsi; ret"),
    "pop rdx": (b"\x5a\xc3", "pop rdx; ret"),
    "pop rax": (b"\x58\xc3", "pop rax; ret"),
    "pop rbp": (b"\x5d\xc3", "pop rbp; ret"),
    "ret":     (b"\xc3", "ret"),
    "leave;ret": (b"\xc9\xc3", "leave; ret"),
    "syscall": (b"\x0f\x05", "syscall"),
    "syscall;ret": (b"\x0f\x05\xc3", "syscall; ret"),
    "jmp rsp": (b"\xff\xe4", "jmp rsp"),
    "call rsp": (b"\xff\xd4", "call rsp"),
    "pop rdi;pop rbp": (b"\x5f\x5d\xc3", "pop rdi; pop rbp; ret"),
    "pop rsi;pop r15": (b"\x5e\x41\x5f\xc3", "pop rsi; pop r15; ret"),
}


WANT32 = {
    "pop eax": (b"\x58\xc3", "pop eax; ret"),
    "pop ebx": (b"\x5b\xc3", "pop ebx; ret"),
    "pop ecx": (b"\x59\xc3", "pop ecx; ret"),
    "pop edx": (b"\x5a\xc3", "pop edx; ret"),
    "pop esi": (b"\x5e\xc3", "pop esi; ret"),
    "pop edi": (b"\x5f\xc3", "pop edi; ret"),
    "pop ebp": (b"\x5d\xc3", "pop ebp; ret"),
    "ret":     (b"\xc3", "ret"),
    "leave;ret": (b"\xc9\xc3", "leave; ret"),
    "int 0x80": (b"\xcd\x80", "int 0x80"),
    "int 0x80;ret": (b"\xcd\x80\xc3", "int 0x80; ret"),
    "jmp esp": (b"\xff\xe4", "jmp esp"),
    "call esp": (b"\xff\xd4", "call esp"),
}


class GadgetFinder:
    _MAX_GADGET_LEN = 6      # bytes before the terminator
    _MAX_PER_NAME = 24

    def __init__(self, elf):
        self.elf = elf
        self._cache = None

    def exec_segments(self):
        for p in self.elf.phdrs:
            if p.type == 1 and (p.flags & 1):
                yield p

    def find_all(self):
        """fixed byte patterns + backtracking search around every `ret`"""
        if self._cache is not None:
            return self._cache
        gadgets = {}
        want = WANT if getattr(self.elf, "bits", 64) == 64 else WANT32
        for p in self.exec_segments():
            code = self.elf.data[p.off:p.off + p.filesz]
            for name, (pat, desc) in want.items():
                start = 0
                while True:
                    i = code.find(pat, start)
                    if i < 0:
                        break
                    start = i + 1
                    addr = p.vaddr + i
                    gadgets.setdefault(name, []).append(
                        Gadget(addr, desc.split("; "), desc))
            self._dynamic_scan(code, p.vaddr, gadgets)
        self._cache = gadgets
        return gadgets

    def _dynamic_scan(self, code, va, gadgets):
        """find gadgets ending in `ret` by walking back 1..N bytes and
        disassembling the window (catches pop rdi/rX compounds and
        leave/syscall/int forms that the fixed byte table misses)"""
        bits = getattr(self.elf, "bits", 64)
        seen = {name: {g.addr for g in lst} for name, lst in gadgets.items()}
        idx = 0
        n = len(code)
        while True:
            idx = code.find(b"\xc3", idx)
            if idx < 0:
                break
            for start in range(max(0, idx - self._MAX_GADGET_LEN), idx):
                window = code[start:idx + 1]
                try:
                    insns = Disasm(window, va + start, bits).linear(len(window))
                except Exception:
                    continue
                if not insns or insns[-1].mnem != "ret":
                    continue
                if sum(i.size for i in insns) != len(window):
                    continue
                if any(i.mnem.startswith(".byte") or i.mnem == "bad" for i in insns):
                    continue
                if len(insns) > 4:
                    continue
                parts = []
                for ins in insns[:-1]:
                    if ins.mnem == "pop" and len(ins.ops) == 1:
                        parts.append(f"pop {ins.ops[0]}")
                    elif ins.mnem == "leave":
                        parts.append("leave")
                    elif ins.mnem == "syscall":
                        parts.append("syscall")
                    elif ins.mnem == "int" and ins.ops and ins.ops[0] == "0x80":
                        parts.append("int 0x80")
                    else:
                        parts = None
                        break
                if parts is None:
                    continue
                if not parts:
                    name = "ret"
                elif len(parts) == 1:
                    name = "leave;ret" if parts[0] == "leave" else (
                        "syscall;ret" if parts[0] == "syscall" else (
                            "int 0x80;ret" if parts[0] == "int 0x80" else parts[0]))
                elif all(part.startswith("pop ") for part in parts):
                    # match the WANT naming convention: pop rdi / pop rsi;pop rbp
                    name = ";".join(parts)
                else:
                    name = ";".join(parts) + ";ret"
                addr = va + start
                bucket = gadgets.setdefault(name, [])
                if addr in seen.get(name, ()) or len(bucket) >= self._MAX_PER_NAME:
                    continue
                desc = color_desc = "; ".join(i.mnem + " " + ", ".join(i.ops)
                                              for i in insns)
                bucket.append(Gadget(addr, [d.strip() for d in desc.split("; ")], desc))
                seen.setdefault(name, set()).add(addr)
                if name == "ret":
                    break
            idx += 1

    def find(self, pattern):
        g = self.find_all()
        return g.get(pattern, [])

    def first(self, pattern):
        l = self.find(pattern)
        return l[0].addr if l else None

    def rop_chain_builder(self):
        """return helper closure to build chains"""
        g = self.find_all()

        def get(name):
            if name not in g or not g[name]:
                raise KeyError(f"gadget not found: {name}")
            return g[name][0].addr

        return get
