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


class GadgetFinder:
    def __init__(self, elf):
        self.elf = elf

    def exec_segments(self):
        for p in self.elf.phdrs:
            if p.type == 1 and (p.flags & 1):
                yield p

    def find_all(self):
        gadgets = {}
        for p in self.exec_segments():
            code = self.elf.data[p.off:p.off + p.filesz]
            for name, (pat, desc) in WANT.items():
                start = 0
                while True:
                    i = code.find(pat, start)
                    if i < 0:
                        break
                    start = i + 1
                    addr = p.vaddr + i
                    gadgets.setdefault(name, []).append(
                        Gadget(addr, desc.split("; "), desc))
        return gadgets

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
