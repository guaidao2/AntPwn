"""AntPwn disassembler: pure-python x86-64 decoder (pattern-recognition subset)
原生 x86-64 反汇编器: 覆盖 CTF 二进制常见指令子集
mov/lea/push/pop/call/jmp/jcc/ret/arithmetic/movzx/test/cdq/syscall/leave ...
author: guaidao2
"""
import struct

CC = {0: "o", 1: "no", 2: "b", 3: "ae", 4: "e", 5: "ne", 6: "be", 7: "a",
      8: "s", 9: "ns", 12: "l", 13: "ge", 14: "le", 15: "g"}
REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REG8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
REG16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
         "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]


class Insn:
    __slots__ = ("addr", "size", "mnem", "ops", "raw")

    def __init__(self, addr, size, mnem, ops, raw):
        self.addr, self.size, self.mnem, self.ops, self.raw = addr, size, mnem, ops, raw

    def __repr__(self):
        return f"{self.addr:#x}: {self.mnem} {', '.join(self.ops)}"

    @property
    def is_ret(self):
        return self.mnem == "ret"

    @property
    def is_call(self):
        return self.mnem == "call"

    @property
    def is_jmp(self):
        return self.mnem == "jmp"

    @property
    def is_jcc(self):
        return self.mnem.startswith("j") and self.mnem != "jmp"

    def target(self):
        """direct branch target address or None"""
        if (self.is_jmp or self.is_call or self.is_jcc) and self.ops:
            try:
                return int(self.ops[0], 16)
            except ValueError:
                return None
        return None


class _Cursor:
    """byte cursor over code with helpers"""
    def __init__(self, code, pos):
        self.code, self.pos = code, pos

    def u8(self):
        v = self.code[self.pos]
        self.pos += 1
        return v

    def i8(self):
        v = struct.unpack_from("<b", self.code, self.pos)[0]
        self.pos += 1
        return v

    def i32(self):
        v = struct.unpack_from("<i", self.code, self.pos)[0]
        self.pos += 4
        return v


class Disasm:
    """linear + recursive-descent disassembly, no external deps"""

    def __init__(self, code, base):
        self.code, self.base = code, base

    # ------------ operand decoding ------------
    def _modrm_mem(self, cur, rex_b, rex_x):
        """decode memory operand after modrm byte consumed; cur.pos at next byte"""
        code = self.code
        modrm = cur._last_modrm
        mod, rm = (modrm >> 6) & 3, modrm & 7
        if rm == 4:  # SIB
            sib = cur.u8()
            scale, idx, base = sib >> 6, (sib >> 3) & 7, sib & 7
            # disp
            if mod == 0 and base == 5:
                disp = cur.i32()
                seg = getattr(cur, "_seg", "")
                return f"[{seg}{disp & 0xffffffffffffffff:#x}]"
            disp = cur.i8() if mod == 1 else (cur.i32() if mod == 2 else 0)
            bs = REG64[base + (rex_b << 3)]
            idxs = ""
            if idx != 4:
                idxs = f"+{REG64[idx + (rex_x << 3)]}*{1 << scale}"
            d = f"+{disp:#x}" if disp > 0 else (f"-{-disp:#x}" if disp else "")
            return f"[{bs}{idxs}{d}]"
        if mod == 0 and rm == 5:
            disp = cur.i32()
            seg = getattr(cur, "_seg", "")
            return f"[{seg}{disp & 0xffffffffffffffff:#x}]"
        disp = cur.i8() if mod == 1 else (cur.i32() if mod == 2 else 0)
        d = f"+{disp:#x}" if disp > 0 else (f"-{-disp:#x}" if disp else "")
        return f"[{REG64[rm + (rex_b << 3)]}{d}]"

    def _rip_mem(self, cur, disp, next_pos):
        ea = self.base + next_pos + disp
        sign = "+" if disp >= 0 else "-"
        return f"[rip{sign}{abs(disp):#x}] => {ea:#x}"

    def decode_one(self, off):
        code, base = self.code, self.base
        addr = base + off
        cur = _Cursor(code, off)
        # ---- legacy prefixes (subset) ----
        seg = ""
        while code[cur.pos] in (0x66, 0x67, 0xf2, 0xf3, 0x64, 0x65, 0x2e, 0x36, 0x3e):
            p = cur.u8()
            if p == 0x64:
                seg = "fs:"
            elif p == 0x65:
                seg = "gs:"
        cur._seg = seg
        # ---- REX ----
        rex = 0
        if 0x40 <= code[cur.pos] <= 0x4f:
            rex = cur.u8()
        rex_w = (rex >> 3) & 1
        rex_r = (rex >> 2) & 1
        rex_x = (rex >> 1) & 1
        rex_b = rex & 1

        b = cur.u8()
        mnem, ops = None, []

        def modrm():
            m = cur.u8()
            cur._last_modrm = m
            return (m >> 6) & 3, (m >> 3) & 7, m & 7

        regs = REG64 if rex_w else REG64  # keep 64 names; fine for our subset

        if 0x50 <= b <= 0x57:
            mnem, ops = "push", [REG64[(b - 0x50) | (rex_b << 3)]]
        elif 0x58 <= b <= 0x5f:
            mnem, ops = "pop", [REG64[(b - 0x58) | (rex_b << 3)]]
        elif 0xb8 <= b <= 0xbf:  # mov r64, imm (imm64 only with REX.W)
            rn = REG64[(b - 0xb8) | (rex_b << 3)]
            if rex_w:
                imm = struct.unpack_from("<Q", code, cur.pos)[0]
                cur.pos += 8
            else:
                imm = cur.i32() & 0xffffffff
            mnem, ops = "mov", [rn, f"0x{imm:x}"]
        elif 0xb0 <= b <= 0xb7:  # mov r8, imm8
            mnem, ops = "mov", [REG8[(b - 0xb0) | (rex_b << 3)], f"0x{cur.u8():x}"]
        elif b in (0x81, 0x83):  # group1: add/or/adc/sbb/and/sub/xor/cmp r/m, imm
            gnames = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
            mod, reg, rm = modrm()
            mnem = gnames[reg]
            if mod == 3:
                dst = REG64[rm + (rex_b << 3)]
                imm = cur.i32() if b == 0x81 else cur.i8()
                ops = [dst, f"0x{imm & 0xffffffff:x}"]
            else:
                if rm == 5 and mod == 0:
                    disp = cur.i32()
                    m = self._rip_mem(cur, disp, cur.pos)
                else:
                    m = self._modrm_mem(cur, rex_b, rex_x)
                imm = cur.i32() if b == 0x81 else cur.i8()
                ops = [m, f"0x{imm & 0xffffffff:x}"]
        elif b in (0x89, 0x8b, 0x8d, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b,
                   0x01, 0x03, 0x85, 0x21, 0x23, 0x09, 0x0b):
            names = {0x89: "mov", 0x8b: "mov", 0x8d: "lea", 0x29: "sub",
                     0x2b: "sub", 0x31: "xor", 0x33: "xor", 0x39: "cmp",
                     0x3b: "cmp", 0x01: "add", 0x03: "add", 0x85: "test",
                     0x21: "and", 0x23: "and", 0x09: "or", 0x0b: "or"}
            mname = names[b]
            mod, reg, rm = modrm()
            rname = REG64[reg + (rex_r << 3)]
            if mod == 3:
                other = REG64[rm + (rex_b << 3)]
                # direction: 8b/2b/33/3b/03/23/0b: r <- r/m
                ops = ([rname, other] if b in (0x8b, 0x2b, 0x33, 0x3b, 0x03, 0x23, 0x0b)
                       else ([other, rname] if b == 0x85 or b == 0x85 else [other, rname]))
                if b == 0x85 or b == 0x39 or b == 0x21 or b == 0x09 or b == 0x31:
                    ops = [other, rname]
                if b in (0x8b, 0x03, 0x23, 0x0b, 0x33, 0x3b, 0x2b):
                    ops = [rname, other]
                mnem = mname
            else:
                if rm == 5 and mod == 0 or (rm == 4):
                    # may be rip-relative (rm==5, mod==0)
                    if rm == 5 and mod == 0:
                        disp = cur.i32()
                        m = self._rip_mem(cur, disp, cur.pos)
                        mnem = mname
                        ops = [rname, m] if b in (0x8b, 0x03, 0x23, 0x0b, 0x33, 0x3b, 0x2b, 0x8d) else [m, rname]
                    else:
                        m = self._modrm_mem(cur, rex_b, rex_x)
                        mnem = mname
                        ops = [rname, m] if b in (0x8b, 0x03, 0x23, 0x0b, 0x33, 0x3b, 0x2b, 0x8d) else [m, rname]
                else:
                    m = self._modrm_mem(cur, rex_b, rex_x)
                    mnem = mname
                    ops = [rname, m] if b in (0x8b, 0x03, 0x23, 0x0b, 0x33, 0x3b, 0x2b, 0x8d) else [m, rname]
        elif b == 0xc7:  # mov r/m, imm32
            mod, reg, rm = modrm()
            if mod == 3:
                dst = REG64[rm + (rex_b << 3)]
                imm = cur.i32()
                mnem, ops = "mov", [dst, f"0x{imm & 0xffffffff:x}"]
            else:
                m = self._modrm_mem(cur, rex_b, rex_x)
                imm = cur.i32()
                mnem, ops = "mov", [m, f"0x{imm & 0xffffffff:x}"]
        elif b == 0xc6:  # mov r/m8, imm8
            mod, reg, rm = modrm()
            if mod == 3:
                mnem, ops = "mov", [REG8[rm + (rex_b << 3)], f"0x{cur.u8():x}"]
            else:
                m = self._modrm_mem(cur, rex_b, rex_x)
                mnem, ops = "mov", [m, f"0x{cur.u8():x}"]
        elif b == 0xe8:  # call rel32
            rel = cur.i32()
            mnem, ops = "call", [f"{base + cur.pos + rel:#x}"]
        elif b == 0xe9:  # jmp rel32
            rel = cur.i32()
            mnem, ops = "jmp", [f"{base + cur.pos + rel:#x}"]
        elif b == 0xeb:  # jmp rel8
            rel = cur.i8()
            mnem, ops = "jmp", [f"{base + cur.pos + rel:#x}"]
        elif 0x70 <= b <= 0x7f:
            rel = cur.i8()
            mnem, ops = f"j{CC[b & 15]}", [f"{base + cur.pos + rel:#x}"]
        elif b == 0xff:
            mod, reg, rm = modrm()
            if reg in (2, 4):
                mn = "call" if reg == 2 else "jmp"
                if mod == 3:
                    mnem, ops = mn, [REG64[rm + (rex_b << 3)]]
                else:
                    m = self._modrm_mem(cur, rex_b, rex_x)
                    mnem, ops = mn, [m]
            elif reg == 6:
                if mod == 3:
                    mnem, ops = "push", [REG64[rm + (rex_b << 3)]]
                else:
                    m = self._modrm_mem(cur, rex_b, rex_x)
                    mnem, ops = "push", [m]
            elif reg == 5:
                mnem, ops = "jmp", ["far"]
            elif reg == 0:
                mnem = "inc"
                ops = [REG64[rm + (rex_b << 3)]] if mod == 3 else [self._modrm_mem(cur, rex_b, rex_x)]
            elif reg == 1:
                mnem = "dec"
                ops = [REG64[rm + (rex_b << 3)]] if mod == 3 else [self._modrm_mem(cur, rex_b, rex_x)]
        elif b == 0xc3:
            mnem = "ret"
        elif b == 0xc9:
            mnem = "leave"
        elif b == 0x90:
            mnem = "nop"
        elif b == 0xcc:
            mnem = "int3"
        elif b == 0x55:
            mnem, ops = "push", ["rbp"]
        elif b in (0xc1, 0xd1, 0xc0, 0xd0, 0xd3):  # shift/rotate group2
            shnames = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"]
            mod, reg, rm = modrm()
            mnem = shnames[reg]
            if mod == 3:
                dst = REG64[rm + (rex_b << 3)]
            else:
                if rm == 5 and mod == 0:
                    disp = cur.i32()
                    dst = self._rip_mem(cur, disp, cur.pos)
                else:
                    dst = self._modrm_mem(cur, rex_b, rex_x)
            if b in (0xc1, 0xc0):
                ops = [dst, f"0x{cur.u8():x}"]
            elif b == 0xd3:
                ops = [dst, "cl"]
            else:
                ops = [dst, "1"]
        elif b == 0x63:  # movsxd r64, r/m32
            mod, reg, rm = modrm()
            if mod == 3:
                src = REG64[rm + (rex_b << 3)]
            else:
                if rm == 5 and mod == 0:
                    disp = cur.i32()
                    src = self._rip_mem(cur, disp, cur.pos)
                else:
                    src = self._modrm_mem(cur, rex_b, rex_x)
            mnem, ops = "movsxd", [REG64[reg + (rex_r << 3)], src]
        elif b == 0x98:
            mnem = "cdqe" if rex_w else "cwde"
        elif b == 0x99:
            mnem = "cqo" if rex_w else "cdq"
        elif b in (0x3c, 0xa8):  # cmp al, imm8 / test al, imm8
            mnem = "cmp" if b == 0x3c else "test"
            ops = ["al", f"0x{cur.u8():x}"]
        elif b in (0x84, 0x88, 0x8a):  # 8-bit test/mov r/m,r
            names8 = {0x84: "test", 0x88: "mov", 0x8a: "mov"}
            mnem = names8[b]
            mod, reg, rm = modrm()
            rname = REG8[reg + (rex_r << 3)]
            if mod == 3:
                other = REG8[rm + (rex_b << 3)]
                ops = [other, rname] if b != 0x8a else [rname, other]
            else:
                if rm == 5 and mod == 0:
                    disp = cur.i32()
                    m = self._rip_mem(cur, disp, cur.pos)
                else:
                    m = self._modrm_mem(cur, rex_b, rex_x)
                ops = [m, rname] if b != 0x8a else [rname, m]
        elif b == 0x0f:
            b2 = cur.u8()
            if 0x80 <= b2 <= 0x8f:
                rel = cur.i32()
                mnem, ops = f"j{CC[b2 & 15]}", [f"{base + cur.pos + rel:#x}"]
            elif b2 == 0x05:
                mnem = "syscall"
            elif b2 == 0x0b:
                mnem = "ud2"
            elif b2 == 0x1e and code[cur.pos] == 0xfa:
                cur.u8()
                mnem = "endbr64"
            elif b2 == 0x1f:  # nop r/m
                mod, reg, rm = modrm()
                if mod != 3:
                    self._modrm_mem(cur, rex_b, rex_x)
                mnem = "nop"
            elif b2 in (0xb6, 0xb7, 0xbe, 0xbf):
                mod, reg, rm = modrm()
                rname = REG64[reg + (rex_r << 3)]
                mn = "movzx" if b2 in (0xb6, 0xb7) else "movsx"
                if mod == 3:
                    src = (REG8 if b2 in (0xb6, 0xbe) else REG16)[rm + (rex_b << 3)]
                    mnem, ops = mn, [rname, src]
                else:
                    if rm == 5 and mod == 0:
                        disp = cur.i32()
                        m = self._rip_mem(cur, disp, cur.pos)
                    else:
                        m = self._modrm_mem(cur, rex_b, rex_x)
                    mnem, ops = mn, [rname, m]
            elif b2 == 0x10 or b2 == 0x11:  # movups
                mod, reg, rm = modrm()
                rname = f"xmm{reg + (rex_r << 3)}"
                if mod == 3:
                    s = f"xmm{rm + (rex_b << 3)}"
                    mnem, ops = "movups", ([rname, s] if b2 == 0x10 else [s, rname])
                else:
                    m = self._modrm_mem(cur, rex_b, rex_x)
                    mnem, ops = "movups", ([rname, m] if b2 == 0x10 else [m, rname])
            elif b2 == 0x05 + 0xc3 - 0xc3:
                mnem = "syscall"
            elif b2 == 0x1e:
                mnem = "endbr"
            else:
                mnem = f"0f{b2:02x}"
        elif b == 0x99:
            mnem = "cqo" if rex_w else "cdq"
        elif b == 0xf3:
            pass
        if mnem is None:
            mnem = f".byte {b:02x}"
            cur.pos = off + 1
        raw = code[off:cur.pos]
        return Insn(addr, cur.pos - off, mnem, ops, raw)

    def linear(self, size):
        out, off = [], 0
        while 0 <= off < size:
            try:
                ins = self.decode_one(off)
            except (IndexError, struct.error):
                ins = Insn(self.base + off, 1, "bad", [], self.code[off:off + 1])
            if ins.size <= 0:
                ins = Insn(self.base + off, 1, "bad", [], self.code[off:off + 1])
            out.append(ins)
            off += ins.size
        return out

    def recursive(self, size, entries):
        seen, insns = set(), {}
        work = list(entries)
        while work:
            off = work.pop()
            while 0 <= off < size:
                if off in seen:
                    break
                try:
                    ins = self.decode_one(off)
                except (IndexError, struct.error):
                    break
                if ins.size <= 0:
                    break
                seen.add(off)
                insns[off] = ins
                if ins.mnem in ("ret", "jmp", "ud2", "bad") or ins.mnem.startswith(".byte"):
                    if ins.is_jmp:
                        t = ins.target()
                        if t is not None and self.base <= t < self.base + size:
                            work.append(t - self.base)
                    break
                if ins.is_call or ins.is_jcc:
                    t = ins.target()
                    if t is not None and self.base <= t < self.base + size:
                        work.append(t - self.base)
                off += ins.size
        return [insns[k] for k in sorted(insns)]
