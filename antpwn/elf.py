"""AntPwn ELF parser: pure-python ELF64 static analysis engine
原生 ELF64 解析: 段/节/符号/PLT/GOT/重定位, 零第三方依赖"""
import struct


class ELFError(Exception):
    pass


class Section:
    __slots__ = ("name", "type", "flags", "addr", "off", "size", "data", "link")


class Symbol:
    __slots__ = ("name", "value", "size", "info", "shndx")


class Reloc:
    __slots__ = ("off", "info", "sym", "type")


class Phdr:
    __slots__ = ("type", "flags", "off", "vaddr", "filesz", "memsz")


class ELF:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ELFError("not an ELF file")
        if d[4] not in (1, 2):
            raise ELFError("bad ELF class")
        self.bits = 64 if d[4] == 2 else 32
        if d[5] != 1:
            raise ELFError("only little-endian ELF supported")
        self.endian = "<"
        if self.bits == 64:
            (self.e_type, self.e_machine, _, self.e_entry, self.e_phoff,
             self.e_shoff, _, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
                "<HHIQQQIHHHHHH", d, 16)
        else:
            (self.e_type, self.e_machine, _, self.e_entry, self.e_phoff,
             self.e_shoff, _, self.e_ehsize, self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from(
                "<HHIIIIIHHHHHH", d, 16)
        self._parse_phdrs()
        self._parse_shdrs()
        self._parse_symbols()
        self._parse_relocs()

    # ---------- program headers ----------
    def _parse_phdrs(self):
        self.phdrs = []
        ent = 56 if self.bits == 64 else 32
        for i in range(self.e_phnum):
            off = self.e_phoff + i * ent
            p = Phdr()
            if self.bits == 64:
                (p.type, p.flags, p.off, p.vaddr, _, p.filesz, p.memsz,
                 _) = struct.unpack_from("<IIQQQQQQ", self.data, off)
            else:
                (p.type, p.off, p.vaddr, _, p.filesz, p.memsz, p.flags,
                 _) = struct.unpack_from("<IIIIIIII", self.data, off)
            self.phdrs.append(p)

    # ---------- sections ----------
    def _parse_shdrs(self):
        self.sections = []
        raw = []
        ent = 64 if self.bits == 64 else 40
        for i in range(self.e_shnum):
            off = self.e_shoff + i * ent
            if self.bits == 64:
                nameoff, stype, flags, addr, off2, size, link, _, align, entsz = \
                    struct.unpack_from("<IIQQQQIIQQ", self.data, off)
            else:
                nameoff, stype, flags, addr, off2, size, link, _, align, entsz = \
                    struct.unpack_from("<IIIIIIIIII", self.data, off)
            s = Section()
            s.type, s.flags, s.addr, s.off, s.size = stype, flags, addr, off2, size
            s.link = link
            s.data = self.data[off2:off2 + size] if stype != 8 and off2 else b""
            s.name = ""
            self.sections.append(s)
            raw.append(nameoff)
        # shstrtab
        if self.e_shstrndx < len(self.sections):
            strtab = self.sections[self.e_shstrndx].data
            for s, no in zip(self.sections, raw):
                if no < len(strtab):
                    end = strtab.find(b"\x00", no)
                    s.name = strtab[no:end].decode("utf-8", "replace")

    def section(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def plt_map(self):
        """map plt stub address -> symbol name (via jmp [got] + relocs)"""
        if hasattr(self, "_plt_map"):
            return self._plt_map
        self._plt_map = {}
        gm = self.got_map()
        rev = {v: k for k, v in gm.items()}
        jump_syms = []
        for r in self.relocs:
            if r.type == 7 and r.sym < len(self.dynsym):
                jump_syms.append(self.dynsym[r.sym].name)
        for secname in (".plt", ".plt.sec", ".plt.got"):
            sec = self.section(secname)
            if not sec or not sec.data:
                continue
            step = 16 if secname == ".plt" else 8
            for i in range(0, len(sec.data) - 6, step):
                d = sec.data
                if d[i] == 0xff and d[i + 1] == 0xa3 and self.bits == 32:
                    # PIC stub: jmp *disp(%ebx)
                    if secname == ".plt" and i >= 16 \
                            and (i - 16) // 16 < len(jump_syms):
                        name = jump_syms[(i - 16) // 16]
                        if name:
                            self._plt_map[sec.addr + i] = name
                    elif secname == ".plt.got":
                        gotplt = self.section(".got.plt")
                        if gotplt:
                            disp = struct.unpack_from("<i", d, i + 2)[0]
                            got = gotplt.addr + disp
                            if got in rev:
                                self._plt_map[sec.addr + i] = rev[got]
                elif d[i] == 0xff and d[i + 1] == 0x25:
                    disp = struct.unpack_from("<i", d, i + 2)[0]
                    if self.bits == 64:
                        got = sec.addr + i + 6 + disp
                    else:
                        got = disp & 0xffffffff   # 32-bit PLT uses an absolute GOT slot
                    if got in rev:
                        self._plt_map[sec.addr + i] = rev[got]
        return self._plt_map

    # ---------- symbols ----------
    def _parse_symbols(self):
        self.symbols = []
        self.dynsym = []
        ent = 24 if self.bits == 64 else 16
        for s in self.sections:
            if s.type not in (2, 11):  # SYMTAB, DYNSYM
                continue
            strtab = self.sections[s.link].data if s.link < len(self.sections) else b""
            for i in range(s.size // ent):
                off = s.off + i * ent
                if self.bits == 64:
                    st_name, st_info, _, _, st_value, st_size = \
                        struct.unpack_from("<IBBHQQ", self.data, off)
                else:
                    st_name, st_value, st_size, st_info, _, _ = \
                        struct.unpack_from("<IIIBBH", self.data, off)
                sym = Symbol()
                sym.name, sym.value, sym.size, sym.info, sym.shndx = (
                    self._cstr(strtab, st_name), st_value, st_size, st_info, 0)
                if s.type == 11:
                    self.dynsym.append(sym)
                if sym.name:
                    self.symbols.append(sym)
        # dedup keep first
        seen = {}
        for sym in self.symbols:
            seen.setdefault(sym.name, sym)
        self.symbols = list(seen.values())

    @staticmethod
    def _cstr(buf, off):
        if off >= len(buf):
            return ""
        e = buf.find(b"\x00", off)
        return buf[off:e].decode("utf-8", "replace")

    def sym(self, name):
        for s in self.symbols:
            if s.name == name:
                return s
        return None

    def sym_at(self, va):
        """innermost function symbol containing virtual address `va`"""
        best = None
        for s in self.symbols:
            if not s.value or not s.size:
                continue
            if s.value <= va < s.value + s.size:
                if best is None or s.size < best.size:
                    best = s
        return best

    def is_writable(self, va):
        for p in self.phdrs:
            if p.type == 1 and (p.flags & 2) \
                    and p.vaddr <= va < p.vaddr + p.memsz:
                return True
        return False

    def functions(self):
        return [s for s in self.symbols
                if s.value and (s.info & 0xf) == 2 and s.name]

    def data_symbols(self):
        return [s for s in self.symbols
                if s.value and (s.info & 0xf) == 1 and s.name]

    # ---------- relocations ----------
    def _parse_relocs(self):
        self.relocs = []
        for s in self.sections:
            if s.type == 4:  # RELA64 / RELA32
                ent, use_addend = (24 if self.bits == 64 else 12), True
            elif s.type == 9:  # REL (64 or 32-bit)
                ent, use_addend = (16 if self.bits == 64 else 8), False
            else:
                continue
            for i in range(s.size // ent):
                r = Reloc()
                if self.bits == 64:
                    if use_addend:
                        r.off, r.info, _ = struct.unpack_from(
                            "<QQq", self.data, s.off + i * ent)
                    else:
                        r.off, r.info = struct.unpack_from(
                            "<QQ", self.data, s.off + i * ent)
                    r.sym, r.type = r.info >> 32, r.info & 0xffffffff
                else:
                    if use_addend:
                        r.off, r.info, _ = struct.unpack_from(
                            "<IIi", self.data, s.off + i * ent)
                    else:
                        r.off, r.info = struct.unpack_from(
                            "<II", self.data, s.off + i * ent)
                    r.sym, r.type = r.info >> 8, r.info & 0xff
                self.relocs.append(r)

    def got_map(self):
        """PLT-relocated symbol -> got slot address"""
        out = {}
        jump_slot = 7 if self.bits == 64 else 7   # R_X86_64_JUMP_SLOT / R_386_JMP_SLOT
        glob_dat = 6 if self.bits == 64 else 6    # GLOB_DAT on both
        for r in self.relocs:
            if r.type not in (jump_slot, glob_dat):
                continue
            if r.sym < len(self.dynsym):
                nm = self.dynsym[r.sym].name
                if nm:
                    out.setdefault(nm, r.off)
        return out


    # ---------- stripped binaries: function discovery ----------
    def exec_segments(self):
        """(vaddr, bytes) of executable PT_LOAD segments"""
        for p in self.phdrs:
            if p.type == 1 and (p.flags & 1):
                yield p.vaddr, self.data[p.off:p.off + p.filesz]

    def _in_exec(self, va, ranges):
        return any(start <= va < start + len(data) for start, data in ranges)

    def discovered_functions(self, max_bytes=0x100000):
        """Heuristic function discovery for stripped binaries.

        Seeds: e_entry, direct call targets from a linear sweep, and common
        prologue byte patterns (endbr64 / push rbp;mov rbp,rsp / sub rsp,N).
        Returns Symbol objects named sub_<addr>, sized up to the next seed.
        """
        segs = list(self.exec_segments())
        if not segs:
            return []
        ranges = [(va, data[:max_bytes]) for va, data in segs]
        total = sum(len(d) for _, d in ranges)
        if total == 0:
            return []

        from .disasm import Disasm

        starts = set()
        prologue_starts = set()
        if self._in_exec(self.e_entry, ranges):
            starts.add(self.e_entry)
        if self.bits == 64:
            prologues = (b"\xf3\x0f\x1e\xfa",      # endbr64
                         b"\x55\x48\x89\xe5",      # push rbp; mov rbp, rsp
                         b"\x48\x83\xec",           # sub rsp, imm8
                         b"\x48\x81\xec")           # sub rsp, imm32
        else:
            prologues = (b"\xf3\x0f\x1e\xfb",      # endbr32
                         b"\x55\x89\xe5",          # push ebp; mov ebp, esp
                         b"\x83\xec",               # sub esp, imm8
                         b"\x81\xec")               # sub esp, imm32
        for va, data in ranges:
            for pat in prologues:
                pos = 0
                while True:
                    i = data.find(pat, pos)
                    if i < 0:
                        break
                    pos = i + 1
                    prologue_starts.add(va + i)
            try:
                for ins in Disasm(data, va, self.bits).linear(len(data)):
                    if ins.is_call:
                        tgt = ins.target()
                        if tgt is not None and self._in_exec(tgt, ranges):
                            starts.add(tgt)
            except Exception:
                continue

        # a prologue-looking sequence mid-function must not become an entry:
        # require a terminator/padding byte before it (or segment start)
        for va, data in ranges:
            for s in list(prologue_starts):
                if not (va <= s < va + len(data)):
                    continue
                rel = s - va
                prev = data[rel - 1] if rel > 0 else 0
                if rel == 0 or prev in (0xC3, 0x90, 0xCC, 0xEB, 0xE9):
                    starts.add(s)
        starts = sorted(s for s in starts if self._in_exec(s, ranges))
        if not starts:
            return []
        out = []
        for idx, addr in enumerate(starts):
            nxt = starts[idx + 1] if idx + 1 < len(starts) else None
            size = (nxt - addr) if nxt and nxt > addr else 0x40
            size = max(0x10, min(size, 0x800))
            sym = Symbol()
            sym.name = f"sub_{addr:x}"
            sym.value = addr
            sym.size = size
            sym.info = 0x12       # STB_GLOBAL | STT_FUNC
            sym.shndx = 0
            out.append(sym)
        return out

    def code_symbols(self):
        """Functions for analysis: real symbols when available, otherwise
        heuristic discovery (stripped binaries)."""
        funcs = [s for s in self.functions() if s.value]
        if len(funcs) >= 8:
            return funcs
        found = self.discovered_functions()
        if not found:
            return funcs
        seen = {s.value for s in funcs}
        merged = list(funcs) + [s for s in found if s.value not in seen]
        merged.sort(key=lambda s: s.value)
        return merged

    # ---------- helpers ----------
    def read(self, vaddr, size):
        for p in self.phdrs:
            if p.type == 1 and p.vaddr <= vaddr < p.vaddr + p.filesz:
                off = p.off + (vaddr - p.vaddr)
                return self.data[off:off + size]
        return b""

    def vaddr_to_off(self, vaddr):
        for p in self.phdrs:
            if p.type == 1 and p.vaddr <= vaddr < p.vaddr + p.filesz:
                return p.off + (vaddr - p.vaddr)
        return None

    # ---------- mitigations ----------
    @property
    def is_pie(self):
        return self.e_type == 3

    @property
    def has_nx(self):
        for p in self.phdrs:
            if p.type == 0x6474e551:  # PT_GNU_STACK
                return not (p.flags & 1)
        return False

    @property
    def has_execstack(self):
        for p in self.phdrs:
            if p.type == 0x6474e551 and (p.flags & 1):
                return True
        return False

    @property
    def canary(self):
        return self.sym("__stack_chk_fail") is not None

    @property
    def relro(self):
        has_bind_now = any(r.sym == 0 for r in [])  # placeholder
        # DT_BIND_NOW / DF_BIND_NOW in .dynamic
        dyn = self.section(".dynamic")
        if dyn is None:
            return "none"
        bind_now = False
        ent = 16 if self.bits == 64 else 8
        for i in range(dyn.size // ent):
            if self.bits == 64:
                tag, val = struct.unpack_from("<qQ", dyn.data, i * ent)
            else:
                tag, val = struct.unpack_from("<iI", dyn.data, i * ent)
            if tag == 24:                       # DT_BIND_NOW
                bind_now = True
            if tag == 30 and (val & 8):         # DT_FLAGS DF_BIND_NOW
                bind_now = True
            if tag == 0x6ffffffb and (val & 1):  # DT_FLAGS_1 DF_1_NOW
                bind_now = True
        if bind_now and any(p.type == 2 for p in self.phdrs if p.flags & 4 and False) is None:
            pass
        # GNU_RELRO segment present?
        relro_seg = any(p.type == 0x6474e552 for p in self.phdrs)
        if bind_now and relro_seg:
            return "full"
        if relro_seg:
            return "partial"
        return "none"

    def strings(self, minlen=4):
        """extract printable strings with vaddr (file-backed)"""
        out = []
        cur, start = b"", 0
        for p in self.phdrs:
            if p.type != 1:
                continue
            seg = self.data[p.off:p.off + p.filesz]
            cur, start = b"", 0
            for i, b in enumerate(seg):
                if 32 <= b < 127:
                    if not cur:
                        start = i
                    cur += bytes([b])
                else:
                    if len(cur) >= minlen:
                        out.append((p.vaddr + start, cur.decode("ascii")))
                    cur = b""
            if len(cur) >= minlen:
                out.append((p.vaddr + start, cur.decode("ascii")))
        return out

    def __repr__(self):
        return f"<ELF {self.path} type={self.e_type} pie={self.is_pie} nx={self.has_nx}>"
