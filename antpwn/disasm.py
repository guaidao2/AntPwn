"""AntPwn disassembler: pure-python x86 / x86-64 decoder (subset)

原生反汇编器: 支持 64 位与 32 位（bits=32）模式，覆盖 CTF 常见指令子集。
Unknown opcodes are skipped with their real length where known, so the
instruction stream does not desynchronise; they are emitted as `.byte XX`.
"""
import struct

CC = {0: "o", 1: "no", 2: "b", 3: "ae", 4: "e", 5: "ne", 6: "be", 7: "a",
      8: "s", 9: "ns", 12: "l", 13: "ge", 14: "le", 15: "g"}

REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
REG16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
         "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
REG16_32 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
REG8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
REG8_32 = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]


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

    def u32(self):
        v = struct.unpack_from("<I", self.code, self.pos)[0]
        self.pos += 4
        return v

    def i64(self):
        v = struct.unpack_from("<q", self.code, self.pos)[0]
        self.pos += 8
        return v


# single-byte opcodes that take a ModRM operand (for unknown-length fallback)
_MODRM1 = {0x62, 0x63, 0x69, 0x6b, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
           0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
           0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3, 0xd8, 0xd9,
           0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xf6, 0xf7, 0xfe, 0xff}
# two-byte 0f opcodes that take a ModRM operand (no immediate)
_MODRM2 = set(range(0x00, 0x02)) | set(range(0x10, 0x18)) | \
    set(range(0x28, 0x30)) | set(range(0x40, 0x50)) | \
    set(range(0x50, 0x77)) | set(range(0x78, 0x80)) | \
    set(range(0x90, 0xa0)) | \
    {0xa3, 0xab, 0xae, 0xaf} | set(range(0xb0, 0xc0)) | \
    {0xc0, 0xc1, 0xc3, 0xc7} | set(range(0xd0, 0xe0)) | \
    set(range(0xe0, 0xe8)) | set(range(0xf0, 0xf8))
# 0f opcodes with ModRM + imm8
_MODRM2_IMM8 = {0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba,
                0xc2, 0xc4, 0xc5, 0xc6}


class Disasm:
    """linear + recursive-descent disassembly, x86-64 (bits=64) or i386 (bits=32)"""

    def __init__(self, code, base, bits=64):
        self.code, self.base = code, base
        self.bits = bits
        self.R = REG64 if bits == 64 else REG32
        self.R8 = REG8 if bits == 64 else REG8_32
        self.R16 = REG16 if bits == 64 else REG16_32

    # ------------ operand decoding ------------
    def _modrm_mem(self, cur, rex_b, rex_x):
        code = self.code
        modrm = cur._last_modrm
        mod, rm = (modrm >> 6) & 3, modrm & 7
        seg = getattr(cur, "_seg", "")
        if rm == 4:  # SIB
            sib = cur.u8()
            scale, idx, base = sib >> 6, (sib >> 3) & 7, sib & 7
            if mod == 0 and base == 5:
                disp = cur.i32()
                if self.bits == 32:
                    return f"[{seg}{disp & 0xffffffff:#x}]"
                return f"[{seg}{disp & 0xffffffffffffffff:#x}]"
            disp = cur.i8() if mod == 1 else (cur.i32() if mod == 2 else 0)
            bs = self.R[base + (rex_b << 3)]
            idxs = ""
            if idx != 4:
                idxs = f"+{self.R[idx + (rex_x << 3)]}*{1 << scale}"
            d = f"+{disp:#x}" if disp > 0 else (f"-{-disp:#x}" if disp else "")
            return f"[{bs}{idxs}{d}]"
        if mod == 0 and rm == 5:
            disp = cur.i32()
            if self.bits == 32:
                return f"[{seg}{disp & 0xffffffff:#x}]"
            return f"[{seg}{disp & 0xffffffffffffffff:#x}]"
        disp = cur.i8() if mod == 1 else (cur.i32() if mod == 2 else 0)
        d = f"+{disp:#x}" if disp > 0 else (f"-{-disp:#x}" if disp else "")
        return f"[{self.R[rm + (rex_b << 3)]}{d}]"

    def _rip_mem(self, cur, disp, next_pos):
        ea = self.base + next_pos + disp
        sign = "+" if disp >= 0 else "-"
        return f"[rip{sign}{abs(disp):#x}] => {ea:#x}"

    def _skip_modrm(self, cur, rex_b=0, rex_x=0):
        """consume a ModRM byte + SIB/displacement, returning (mod, reg, rm)"""
        code = self.code
        if cur.pos >= len(code):
            raise IndexError
        modrm = cur.u8()
        cur._last_modrm = modrm
        mod, reg, rm = (modrm >> 6) & 3, (modrm >> 3) & 7, modrm & 7
        if mod == 3:
            return mod, reg, rm
        if rm == 4:
            if cur.pos >= len(code):
                raise IndexError
            sib = cur.u8()
            base = sib & 7
            if mod == 0 and base == 5:
                cur.i32()
            elif mod == 1:
                cur.i8()
            elif mod == 2:
                cur.i32()
        else:
            if mod == 0 and rm == 5:
                cur.i32()
            elif mod == 1:
                cur.i8()
            elif mod == 2:
                cur.i32()
        return mod, reg, rm

    def _unknown_len(self, cur, first, off):
        """best-effort instruction length for an unimplemented opcode"""
        cur.pos = off
        if first == 0x0f:
            cur.u8()
            if cur.pos >= len(self.code):
                return 2
            b2 = cur.u8()
            if b2 in _MODRM2:
                try:
                    self._skip_modrm(cur)
                except IndexError:
                    return 2
                if b2 in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba):
                    cur.u8()
                return cur.pos - off
            return 2
        cur.u8()
        if first in _MODRM1:
            try:
                _, reg, _ = self._skip_modrm(cur)
            except IndexError:
                return cur.pos - off
            if first in (0x69, 0x81, 0xc7):
                cur.i32() if first != 0x69 else cur.i32()
            elif first in (0x6b, 0x80, 0x82, 0x83, 0xc0, 0xc1, 0xc6,
                           0xd0, 0xd1, 0xd2, 0xd3):
                cur.u8()
            elif first == 0xf7 and reg in (0, 1):
                cur.u32()
            elif first == 0xf6 and reg in (0, 1):
                cur.u8()
        return cur.pos - off

    def decode_one(self, off):
        code, base = self.code, self.base
        addr = base + off
        cur = _Cursor(code, off)
        seg = ""
        while cur.pos < len(code) and code[cur.pos] in (
                0x66, 0x67, 0xf2, 0xf3, 0x64, 0x65, 0x2e, 0x36, 0x3e):
            p = cur.u8()
            if p == 0x64:
                seg = "fs:"
            elif p == 0x65:
                seg = "gs:"
        cur._seg = seg
        rex = 0
        if self.bits == 64 and cur.pos < len(code) and 0x40 <= code[cur.pos] <= 0x4f:
            rex = cur.u8()
        rex_w = (rex >> 3) & 1
        rex_r = (rex >> 2) & 1
        rex_x = (rex >> 1) & 1
        rex_b = rex & 1
        if cur.pos >= len(code):
            raise IndexError

        b = cur.u8()
        mnem, ops = None, []

        def modrm():
            if cur.pos >= len(code):
                raise IndexError
            m = cur.u8()
            cur._last_modrm = m
            return (m >> 6) & 3, (m >> 3) & 7, m & 7

        def mem_or_reg(mod, reg, rm):
            if mod == 3:
                return self.R[rm + (rex_b << 3)]
            return self._modrm_mem(cur, rex_b, rex_x)

        # ---- i386 0x40-0x4f are inc/dec; 0x63 is movsxd (64) / arpl (32) ----
        if self.bits == 32 and 0x40 <= b <= 0x4f:
            mnem, ops = ("inc" if b < 0x48 else "dec"), [self.R[b & 7]]
        elif b == 0x63:
            mod, reg, rm = modrm()
            if self.bits == 64:
                rname = self.R[reg + (rex_r << 3)]
                m = (self.R[rm + (rex_b << 3)] if mod == 3 else
                     self._modrm_mem(cur, rex_b, rex_x))
                mnem, ops = "movsxd", [rname, m]
            else:
                rname = self.R16[reg]
                m = (self.R16[rm] if mod == 3 else
                     self._modrm_mem(cur, rex_b, rex_x))
                mnem, ops = "arpl", [m, rname]
        # ---- single-byte arithmetic / logic groups (00..3b) ----
        elif b < 0x40 and (b & 7) in (0, 1, 2, 3) and (b >> 3) < 8:
            gname = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][b >> 3]
            mod, reg, rm = modrm()
            if b & 3 in (0, 1):
                rname = self.R[reg + (rex_r << 3)]
                m = mem_or_reg(mod, reg, rm)
                if b & 1:
                    mnem, ops = gname, [m, rname]
                else:
                    mnem, ops = gname, [rname, m]
            else:  # 8-bit variants
                rname = self.R8[reg + (rex_r << 3)]
                m = self.R8[rm + (rex_b << 3)] if mod == 3 else self._modrm_mem(cur, rex_b, rex_x)
                if b & 1:
                    mnem, ops = gname, [m, rname]
                else:
                    mnem, ops = gname, [rname, m]
        elif 0x50 <= b <= 0x57:
            mnem, ops = "push", [self.R[(b - 0x50) | (rex_b << 3)]]
        elif 0x58 <= b <= 0x5f:
            mnem, ops = "pop", [self.R[(b - 0x58) | (rex_b << 3)]]
        elif b == 0x68:
            imm = cur.i32()
            mnem, ops = "push", [f"0x{imm & 0xffffffff:x}"]
        elif b == 0x6a:
            imm = cur.i8()
            mnem, ops = "push", [f"0x{imm & 0xffffffff:x}"]
        elif b == 0x69 or b == 0x6b:  # imul r, r/m, imm
            mod, reg, rm = modrm()
            rname = self.R[reg + (rex_r << 3)]
            m = mem_or_reg(mod, reg, rm)
            imm = cur.i32() if b == 0x69 else cur.i8()
            mnem, ops = "imul", [rname, m, f"0x{imm & 0xffffffff:x}"]
        elif b == 0x0f:
            b2 = cur.u8()
            if 0x80 <= b2 <= 0x8f:
                rel = cur.i32()
                mnem, ops = f"j{CC[b2 & 15]}", [f"{base + cur.pos + rel:#x}"]
            elif b2 == 0x05:
                mnem = "syscall"
            elif b2 == 0x34:
                mnem = "sysenter"
            elif b2 == 0x0b:
                mnem = "ud2"
            elif b2 == 0x31:
                mnem = "rdtsc"
            elif b2 == 0xa2:
                mnem = "cpuid"
            elif b2 == 0x1e and cur.pos < len(code) and code[cur.pos] in (0xfa, 0xfb):
                cur.u8()
                mnem = "endbr64" if self.bits == 64 else "endbr32"
            elif b2 == 0x1f:  # nop r/m
                mod, reg, rm = modrm()
                if mod != 3:
                    self._modrm_mem(cur, rex_b, rex_x)
                mnem = "nop"
            elif 0x40 <= b2 <= 0x4f:  # cmovcc
                mod, reg, rm = modrm()
                rname = self.R[reg + (rex_r << 3)]
                m = mem_or_reg(mod, reg, rm)
                mnem, ops = f"cmov{CC[b2 & 15]}", [rname, m]
            elif 0x90 <= b2 <= 0x9f:  # setcc
                mod, reg, rm = modrm()
                m = mem_or_reg(mod, reg, rm)
                mnem, ops = f"set{CC[b2 & 15]}", [m]
            elif b2 == 0xaf:  # imul r, r/m
                mod, reg, rm = modrm()
                rname = self.R[reg + (rex_r << 3)]
                m = mem_or_reg(mod, reg, rm)
                mnem, ops = "imul", [rname, m]
            elif b2 in (0xb6, 0xb7, 0xbe, 0xbf):
                mod, reg, rm = modrm()
                rname = self.R[reg + (rex_r << 3)]
                mn = "movzx" if b2 in (0xb6, 0xb7) else "movsx"
                if mod == 3:
                    src = (self.R8 if b2 in (0xb6, 0xbe) else self.R16)[
                        rm + (rex_b << 3)]
                    mnem, ops = mn, [rname, src]
                else:
                    if rm == 5 and mod == 0 and self.bits == 64:
                        disp = cur.i32()
                        m = self._rip_mem(cur, disp, cur.pos)
                    else:
                        m = self._modrm_mem(cur, rex_b, rex_x)
                    mnem, ops = mn, [rname, m]
            elif 0xc8 <= b2 <= 0xcf:  # bswap r32/r64 (reg-encoded, no ModRM)
                mnem, ops = "bswap", [self.R[(b2 - 0xc8) + (rex_b << 3)]]
            elif b2 == 0x77:
                mnem = "emms"
            elif b2 in (0x38, 0x3a) and cur.pos < len(code):
                cur.u8()                      # third opcode byte
                if b2 == 0x3a:
                    try:
                        self._skip_modrm(cur)
                        cur.u8()
                    except IndexError:
                        pass
                else:
                    try:
                        self._skip_modrm(cur)
                    except IndexError:
                        pass
                mnem = f"0f{b2:02x}"
            elif b2 == 0x10 or b2 == 0x11:  # movups
                mod, reg, rm = modrm()
                rname = f"xmm{reg + (rex_r << 3)}"
                if mod == 3:
                    s = f"xmm{rm + (rex_b << 3)}"
                    mnem, ops = "movups", ([rname, s] if b2 == 0x10 else [s, rname])
                else:
                    m = self._modrm_mem(cur, rex_b, rex_x)
                    mnem, ops = "movups", ([rname, m] if b2 == 0x10 else [m, rname])
            else:
                mnem = f"0f{b2:02x}"
                try:
                    if b2 in _MODRM2_IMM8:
                        self._skip_modrm(cur)
                        cur.u8()
                    elif b2 in _MODRM2:
                        self._skip_modrm(cur)
                except IndexError:
                    pass
        elif 0x70 <= b <= 0x7f:
            rel = cur.i8()
            mnem, ops = f"j{CC[b & 15]}", [f"{base + cur.pos + rel:#x}"]
        elif b in (0x80, 0x81, 0x82, 0x83):  # group1
            gnames = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
            mod, reg, rm = modrm()
            mnem = gnames[reg]
            m = mem_or_reg(mod, reg, rm)
            if b == 0x81:
                imm = cur.i32()
            else:
                imm = cur.i8()
            ops = [m, f"0x{imm & 0xffffffff:x}"]
        elif b in (0x84, 0x85):  # test r/m, r
            mod, reg, rm = modrm()
            rname = (self.R8 if b == 0x84 else self.R)[reg + (rex_r << 3)]
            m = ((self.R8[rm + (rex_b << 3)]) if mod == 3 else
                 self._modrm_mem(cur, rex_b, rex_x))
            mnem, ops = "test", [m, rname]
        elif b in (0x86, 0x87):  # xchg
            mod, reg, rm = modrm()
            rname = (self.R8 if b == 0x86 else self.R)[reg + (rex_r << 3)]
            m = ((self.R8[rm + (rex_b << 3)]) if mod == 3 else
                 self._modrm_mem(cur, rex_b, rex_x))
            mnem, ops = "xchg", [m, rname]
        elif b in (0x88, 0x89, 0x8a, 0x8b):  # mov
            mod, reg, rm = modrm()
            byte = b in (0x88, 0x8a)
            regs = self.R8 if byte else self.R
            rn = regs[reg + (rex_r << 3)]
            m = (regs[rm + (rex_b << 3)] if mod == 3 else
                 self._modrm_mem(cur, rex_b, rex_x))
            if b in (0x8a, 0x8b):
                ops = [rn, m]
            else:
                ops = [m, rn]
            mnem = "mov"
        elif b == 0x8d:  # lea
            mod, reg, rm = modrm()
            rname = self.R[reg + (rex_r << 3)]
            if rm == 5 and mod == 0 and self.bits == 64:
                disp = cur.i32()
                mnem, ops = "lea", [rname, self._rip_mem(cur, disp, cur.pos)]
            else:
                mnem = "lea"
                ops = [rname, self._modrm_mem(cur, rex_b, rex_x)]
        elif b == 0x8f:  # pop r/m
            mod, reg, rm = modrm()
            m = mem_or_reg(mod, reg, rm)
            mnem, ops = "pop", [m]
        elif b in (0x90,):  # nop / xchg eax, r
            mnem = "nop"
        elif b == 0x91:
            mnem, ops = "xchg", [self.R[0], self.R[1]]
        elif b == 0x98:
            mnem = "cdqe" if (self.bits == 64 and rex_w) else "cwde"
        elif b == 0x99:
            mnem = "cqo" if (self.bits == 64 and rex_w) else "cdq"
        elif b in (0x9c, 0x9d):
            mnem = "pushf" if b == 0x9c else "popf"
        elif b in (0x9e, 0x9f):
            mnem = "sahf" if b == 0x9e else "lahf"
        elif b in (0x60, 0x61):
            mnem = "pusha" if b == 0x60 else "popa"
        elif b in (0xa8, 0xa9):  # test al/eax, imm
            imm_size = 1 if b == 0xa8 else (4 if self.bits == 32 or not rex_w else 8)
            imm = cur.u8() if imm_size == 1 else (cur.i32() if imm_size == 4 else cur.i64())
            mnem = "test"
            ops = [("al" if b == 0xa8 else ("eax" if imm_size == 4 else "rax")),
                   f"0x{imm & 0xffffffffffffffff:x}"]
        elif b in (0xa4, 0xa5, 0xa6, 0xa7, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf):
            mnem = {0xa4: "movsb", 0xa5: "movs", 0xa6: "cmpsb", 0xa7: "cmps",
                    0xaa: "stosb", 0xab: "stos", 0xac: "lodsb", 0xad: "lods",
                    0xae: "scasb", 0xaf: "scas"}[b]
        elif 0xb0 <= b <= 0xb7:
            mnem, ops = "mov", [self.R8[(b - 0xb0) | (rex_b << 3)],
                                f"0x{cur.u8():x}"]
        elif 0xb8 <= b <= 0xbf:
            rn = self.R[(b - 0xb8) | (rex_b << 3)]
            if self.bits == 64 and rex_w:
                imm = cur.i64()
            else:
                imm = cur.i32()
            mnem, ops = "mov", [rn, f"0x{imm & 0xffffffffffffffff:x}" if self.bits == 64
                                else f"0x{imm & 0xffffffff:x}"]
        elif b in (0xc0, 0xc1, 0xd0, 0xd1, 0xd2, 0xd3):
            shnames = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"]
            mod, reg, rm = modrm()
            mnem = shnames[reg]
            m = mem_or_reg(mod, reg, rm)
            if b in (0xc0, 0xc1):
                ops = [m, f"0x{cur.u8():x}"]
            elif b in (0xd2, 0xd3):
                ops = [m, "cl"]
            else:
                ops = [m, "1"]
        elif b == 0xc2:
            imm = struct.unpack_from("<H", code, cur.pos)[0]
            cur.pos += 2
            mnem, ops = "ret", [f"0x{imm:x}"]
        elif b == 0xc3:
            mnem = "ret"
        elif b in (0xc6, 0xc7):
            mod, reg, rm = modrm()
            m = mem_or_reg(mod, reg, rm)
            if b == 0xc6:
                imm = cur.u8()
            else:
                imm = cur.i32()
            mnem, ops = "mov", [m, f"0x{imm & 0xffffffff:x}"]
        elif b == 0xc8:  # enter imm16, imm8
            cur.pos += 3
            mnem = "enter"
        elif b == 0xc9:
            mnem = "leave"
        elif b == 0xcc:
            mnem = "int3"
        elif b == 0xcd:
            imm = cur.u8()
            mnem, ops = "int", [f"0x{imm:x}"]
        elif b == 0xce:
            mnem = "into"
        elif b == 0xcf:
            mnem = "iret"
        elif b == 0xe8:
            rel = cur.i32()
            mnem, ops = "call", [f"{base + cur.pos + rel:#x}"]
        elif b == 0xe9:
            rel = cur.i32()
            mnem, ops = "jmp", [f"{base + cur.pos + rel:#x}"]
        elif b == 0xeb:
            rel = cur.i8()
            mnem, ops = "jmp", [f"{base + cur.pos + rel:#x}"]
        elif b == 0xf4:
            mnem = "hlt"
        elif b in (0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd):
            mnem = {0xf8: "clc", 0xf9: "stc", 0xfa: "cli",
                    0xfb: "sti", 0xfc: "cld", 0xfd: "std"}[b]
        elif b in (0xf6, 0xf7):  # group3
            mod, reg, rm = modrm()
            m = mem_or_reg(mod, reg, rm)
            if reg in (0, 1):
                imm = cur.u8() if b == 0xf6 else (cur.i32() if self.bits == 32 or not rex_w else cur.i64())
                mnem, ops = ("test", [m, f"0x{imm & 0xffffffffffffffff:x}"])
            else:
                mnem, ops = ({2: "not", 3: "neg", 4: "mul", 5: "imul",
                              6: "div", 7: "idiv"}[reg], [m])
        elif b in (0xfe, 0xff):  # group4/5
            mod, reg, rm = modrm()
            m = mem_or_reg(mod, reg, rm)
            if b == 0xfe:
                mnem, ops = ("inc" if reg == 0 else "dec"), [m]
            elif reg == 0:
                mnem, ops = "inc", [m]
            elif reg == 1:
                mnem, ops = "dec", [m]
            elif reg == 2:
                mnem, ops = "call", [m]
            elif reg == 4:
                mnem, ops = "jmp", [m]
            elif reg == 6:
                mnem, ops = "push", [m]
            else:
                mnem, ops = f"grp5_{reg}", [m]
        elif b in (0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf):
            mod, reg, rm = modrm()
            if mod != 3:
                self._modrm_mem(cur, rex_b, rex_x)
            mnem = f"fpu_{b:02x}"
        elif b in (0xa0, 0xa1, 0xa2, 0xa3):  # mov moffs
            size = 4 if (b in (0xa0, 0xa2) or self.bits == 32) else 8
            addr_v = cur.u32() if size == 4 else struct.unpack_from("<Q", code, cur.pos)[0]
            if size == 8:
                cur.pos += 8
            mnem = "mov"
            ops = [f"[0x{addr_v:x}]", ("al" if b in (0xa0, 0xa2) else "eax")]
        if mnem is None:
            opcode_off = cur.pos - 1
            try:
                # count from the opcode byte, then add the prefix/REX bytes
                total = self._unknown_len(cur, b, opcode_off) + (opcode_off - off)
            except (IndexError, struct.error):
                total = cur.pos - off or 1
            total = max(total, 1)
            mnem = ".byte " + code[off:off + total].hex()
            ops = []
            return Insn(addr, total, mnem, ops, code[off:off + total])
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
