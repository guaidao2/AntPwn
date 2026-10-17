"""AntPwn decompiler: lift disassembly to C-like pseudo-code.

Pipeline (inspired by the Ghidra/rz-ghidra decompiler, implemented from
scratch in pure Python):

    disassemble -> IR lift (expressions / statements) -> CFG (dominators,
    post-dominators, natural loops) -> symbolic env + simplification ->
    stack-slot recovery -> control-flow structuring -> C-like render.

`render()` stays plain text on purpose: the scanner parses it for the
`char vN[N];` / `name@plt(...)` patterns.  `render_ansi()` adds rz-ghidra style
syntax colours for terminals (used by `repl` / CLI / the gdb plugin).
"""
from .disasm import REG64, Disasm
from .ir import (Lifter, invert, render as render_expr, const)
from . import color


class PseudoFunc:
    def __init__(self, name, addr, size):
        self.name, self.addr, self.size = name, addr, size
        self.lines = []          # (indent, text)
        self.calls = []          # called function names
        self.stack_vars = {}     # rsp/rbp offsets -> var names
        self.string_refs = {}    # lea targets -> strings
        self.effects = []        # interesting side effects
        self.var_decls = []      # "char v0[64];"
        self.params = []         # recovered parameter names (unused for now)
        self.engine = "ir"       # "ir" or "legacy" (fallback lifter)

    def text(self):
        return "\n".join(t for _, t in self.lines)


def _stmt_exprs(st):
    kind = st[0]
    if kind == "assign":
        return (st[2],)
    if kind == "store":
        return (st[1], st[2])
    if kind == "call":
        return tuple(st[2])
    return ()


def _collect_calls(e, out):
    if not isinstance(e, tuple):
        return
    if e[0] == "call":
        out.add((e[1], e[2]))
        for a in e[2]:
            _collect_calls(a, out)
    elif e[0] in ("bin",):
        _collect_calls(e[2], out)
        _collect_calls(e[3], out)
    elif e[0] == "un":
        _collect_calls(e[2], out)
    elif e[0] == "mem":
        _collect_calls(e[1], out)
        if e[2] is not None:
            _collect_calls(e[2], out)


class _Structurer:
    """turn a lifted FunctionIR into indented pseudo-code lines.

    Rules that matter for readability/correctness:
    - if/else is emitted in source order (taken branch is ordered by address);
    - empty branches are marked, never silently dropped;
    - loop-header statements move inside the loop (while (1) + break), so a
      per-iteration menu()/fgets() is not hoisted out of the loop;
    - labels are emitted at the target block, collected from gotos;
    - irreducible flow falls back to labels+goto instead of wrong nesting.
    """

    def __init__(self, ir, fname):
        self.ir = ir
        self.fname = fname
        self.lines = []
        self.level = 0
        self.emitted = set()
        self.loop_by_header = {}
        for header, latch, body in ir.loops:
            self.loop_by_header[header] = (latch, body)
        self.loop_stack = []
        self.label_needed = set()
        for addr in ir.order:
            block = ir.blocks[addr]
            term = block.term
            if term and term[0] in ("jcc", "jmp") and term[-1] in ir.blocks:
                self.label_needed.add(term[-1])
        self.goto_targets = set()

    # ---------------- line helpers ----------------
    def line(self, text, level=None):
        self.lines.append((self.level if level is None else level, text))

    def goto(self, addr):
        self.goto_targets.add(addr)
        self.line(f"goto L_{addr:x};")

    def emit_stmts(self, block):
        for st in block.stmts:
            kind = st[0]
            if kind == "assign":
                self.line(f"{render_expr(st[1])} = {render_expr(st[2])};")
            elif kind == "store":
                dst, src = st[1], st[2]
                if dst[0] == "var":
                    self.line(f"{dst[1]} = {render_expr(src)};")
                elif dst[0] == "mem":
                    base, idx = dst[1], dst[2]
                    if idx is not None:
                        self.line(f"{render_expr(base)}[{render_expr(idx)}] = "
                                  f"{render_expr(src)};")
                    else:
                        self.line(f"*{render_expr(base)} = {render_expr(src)};")
                else:
                    self.line(f"{render_expr(dst)} = {render_expr(src)};")
            elif kind == "call":
                args = ", ".join(render_expr(a) for a in st[2]) or ""
                self.line(f"{st[1]}({args});")
            elif kind == "syscall":
                self.line("syscall();")
            elif kind == "comment":
                self.line(f"// {st[1]}")
        self.emitted.add(block.addr)

    def capture(self, fn):
        """emit into a temporary buffer (for empty-branch detection)"""
        saved_lines, saved_level = self.lines, self.level
        self.lines, self.level = [], saved_level + 1
        fn()
        out = self.lines
        self.lines, self.level = saved_lines, saved_level
        return out

    # ---------------- main ----------------
    def emit(self):
        self.emit_region(self.ir.entry, None)
        missing = [a for a in self.ir.order if a not in self.emitted]
        if missing:
            dead = [a for a in missing if not self.ir.preds.get(a)]
            if len(dead) == len(missing):
                self.line("// %d dead block(s) omitted" % len(dead))
            else:
                self.line("// %d block(s) not emitted by the structurer (goto fallback)"
                          % len(missing))
        # keep only labels that are actually targeted
        used = {line.split("L_")[1].split(":")[0].split()[0]
                for _, line in self.lines if "goto L_" in line}
        out = []
        for ind, text in self.lines:
            if text.startswith("L_") and text.endswith(":"):
                name = text[2:-1]
                if name not in used:
                    continue
            out.append((ind, text))
        return out

    def emit_region(self, addr, stop):
        guard = 0
        while addr is not None and addr != stop and addr not in self.emitted:
            guard += 1
            if guard > 4000:
                self.line("// [structuring aborted]")
                return
            block = self.ir.blocks.get(addr)
            if block is None:
                return
            if addr in self.label_needed and addr in self.goto_targets:
                self.line(f"L_{addr:x}:", level=0)
            nxt = self.emit_one(block, stop)
            if nxt == addr:
                return
            addr = nxt

    def emit_one(self, block, stop):
        addr = block.addr
        term = block.term
        if addr in self.loop_by_header and addr not in self.emitted:
            return self.emit_loop(addr)
        self.emit_stmts(block)
        if term is None:
            return self.ir.next_block(addr)
        if term[0] == "ret":
            expr = term[1]
            if expr is not None and expr[0] == "call" and expr[1] == "syscall" \
                    and self.lines and self.lines[-1][1].strip() == "syscall();":
                expr = None      # avoid "syscall(); return syscall();" duplication
            if expr is not None and not (expr[0] == "reg"
                                         and expr[1] in ("rax", "eax")):
                self.line(f"return {render_expr(expr)};")
            else:
                self.line("return;")
            return None
        if term[0] == "jmp":
            tgt = term[1]
            for header, body, exit_addr in reversed(self.loop_stack):
                if tgt == header:
                    self.line("continue;")
                    return None
                if tgt == exit_addr and tgt not in body:
                    self.line("break;")
                    return None
            if tgt == stop:
                return stop
            if tgt in self.emitted:
                self.goto(tgt)
                return None
            nxt = self.ir.next_block(addr)
            if tgt == nxt:
                return tgt
            return tgt
        if term[0] == "jcc":
            cond = term[1]
            tgt = term[2]
            fall = self.ir.next_block(addr)
            if cond[0] == "const":
                if not cond[1]:
                    return fall
                if tgt in self.emitted:
                    return None
                self.emit_region(tgt, None)
                return None
            for header, body, exit_addr in reversed(self.loop_stack):
                if tgt == exit_addr and fall is not None and fall in body:
                    self.line(f"if ({render_expr(cond)}) break;")
                    return fall
            if tgt in self.emitted:
                self.line(f"if ({render_expr(cond)}) goto L_{tgt:x};")
                self.goto_targets.add(tgt)
                return fall
            join = self.ir.immediate_postdom(addr)
            if join is not None and join != addr and join not in self.emitted:
                self.emit_cond(cond, tgt, fall, join)
                return join
            # no clean join: conditional goto + fallthrough
            self.line(f"if ({render_expr(cond)}) {{")
            self.level += 1
            self.emit_region(tgt, None)
            self.level -= 1
            self.line("}")
            return fall
        return self.ir.next_block(addr)

    # ---------------- conditionals ----------------
    def emit_cond(self, cond, tgt, fall, join):
        """emit if / if-else in source order with empty-branch markers"""
        if fall is None:
            return
        then_lines = self.capture(lambda: self.emit_region(tgt, join))
        else_lines = self.capture(lambda: self.emit_region(fall, join))
        if not then_lines and not else_lines:
            self.line("// (empty conditional)")
            return
        if not else_lines:
            self.line(f"if ({render_expr(cond)}) {{")
            self.lines.extend(then_lines)
            self.line("}")
            return
        if not then_lines:
            self.line(f"if ({render_expr(invert(cond))}) {{")
            self.lines.extend(else_lines)
            self.line("}")
            return
        # both non-empty: keep address order so else-if chains read naturally
        if fall is not None and tgt is not None and fall < tgt:
            self.line(f"if ({render_expr(invert(cond))}) {{")
            self.lines.extend(else_lines)
            self.line("} else {")
            self.lines.extend(then_lines)
            self.line("}")
        else:
            self.line(f"if ({render_expr(cond)}) {{")
            self.lines.extend(then_lines)
            self.line("} else {")
            self.lines.extend(else_lines)
            self.line("}")

    # ---------------- loops ----------------
    def emit_loop(self, header):
        latch, body = self.loop_by_header[header]
        block = self.ir.blocks[header]
        term = block.term
        # which successor leaves the loop?
        tgt = term[2] if term is not None and term[0] == "jcc" else None
        fall = self.ir.next_block(header)
        inside = [s for s in (tgt, fall) if s is not None and s in body]
        outside = [s for s in (tgt, fall) if s is not None and s not in body]
        exit_addr = outside[0] if outside else None
        if exit_addr is None:
            for cand in self.ir.order:
                if cand not in body and cand > header:
                    exit_addr = cand
                    break
        self.loop_stack.append((header, body, exit_addr))
        # header statements with a conditional exit: while (1) { stmts; if exit break; ... }
        if term is not None and term[0] == "jcc" and block.stmts and inside:
            exit_cond = term[1] if tgt == exit_addr else invert(term[1])
            self.line("while (1) {")
            self.level += 1
            self.emit_stmts(block)
            self.line(f"if ({render_expr(exit_cond)}) break;")
            body_entry = [s for s in (tgt, fall) if s in body][0]
            self.emit_region(body_entry, header)
            self.level -= 1
            self.line("}")
            self.loop_stack.pop()
            return exit_addr
        self.emit_stmts(block)
        body_entry = inside[0] if inside else fall
        if body_entry is None:
            self.level += 1
            self.line("// [loop body not found]")
            self.level -= 1
            self.loop_stack.pop()
            return exit_addr
        if term is not None and term[0] == "jcc" and inside:
            cond = term[1]
            while_cond = invert(cond) if tgt == exit_addr else cond
            self.line(f"while ({render_expr(while_cond)}) {{")
            self.level += 1
            self.emit_region(body_entry, header)
            self.level -= 1
            self.line("}")
        elif term is not None and term[0] == "jmp":
            self.line("do {")
            self.level += 1
            self.emit_region(body_entry, header)
            self.level -= 1
            lblock = self.ir.blocks.get(latch)
            tail = "1"
            if lblock is not None and lblock.term and lblock.term[0] == "jcc":
                lc = lblock.term[1]
                ltgt = lblock.term[2]
                tail = render_expr(lc if ltgt == header else invert(lc))
            self.line(f"}} while ({tail});")
        else:
            self.line("while (1) {")
            self.level += 1
            self.emit_region(body_entry, header)
            self.level -= 1
            self.line("}")
        self.loop_stack.pop()
        return exit_addr


class Decompiler:
    def __init__(self, elf, strings=None):
        self.elf = elf
        self.strmap = {}
        for va, s in (strings if strings is not None else elf.strings(minlen=1)):
            self.strmap.setdefault(va, s)

    def function(self, sym):
        code = self.elf.read(sym.value, sym.size or 0x200)
        if not code:
            return None
        dis = Disasm(code, sym.value, self.elf.bits)
        insns = dis.recursive(len(code), [0])
        pf = PseudoFunc(sym.name, sym.value, sym.size)
        try:
            self._lift_new(sym, insns, pf)
        except Exception:
            pf = PseudoFunc(sym.name, sym.value, sym.size)
            self._lift_legacy(insns, pf, sym.value)
        if not pf.lines:
            pf = PseudoFunc(sym.name, sym.value, sym.size)
            pf.engine = "legacy"
            self._lift_legacy(insns, pf, sym.value)
        return pf

    # ------------------------------------------------------------------
    def _fname(self, tgt):
        if tgt is None:
            return "func_ptr"
        pm = self.elf.plt_map()
        if tgt in pm:
            return pm[tgt] + "@plt"
        for s in self.elf.functions():
            if s.value == tgt:
                return s.name
        return f"sub_{tgt:x}"

    def _lift_new(self, sym, insns, pf):
        from .ir import FunctionIR
        ir = FunctionIR(sym.name, insns[0].addr if insns else sym.value)
        lifter = Lifter(self.elf, ir, sym.value)
        lifter.lift(insns, self.strmap)
        # calls whose result is used in an expression are inlined, so drop
        # the duplicate standalone statement
        used = set()
        for block in ir.blocks.values():
            for st in block.stmts:
                for expr in _stmt_exprs(st):
                    _collect_calls(expr, used)
            term = block.term
            if term and term[0] == "ret" and term[1] is not None:
                _collect_calls(term[1], used)
            elif term and term[0] == "jcc":
                _collect_calls(term[1], used)
        for addr in ir.order:
            block = ir.blocks[addr]
            block.stmts = [st for st in block.stmts
                           if not (st[0] == "call" and (st[1], st[2]) in used)]
        pf.calls = list(dict.fromkeys(ir.calls))
        pf.effects = list(ir.effects)
        pf.string_refs = dict(ir.strings)
        struct = _Structurer(ir, sym.name)
        lines = struct.emit()
        pf.lines = lines
        pf.stack_vars = {str(off): name for off, name in ir.stack.slots.items()}
        pf.var_decls = self._decls(ir)
        params = list(getattr(ir.stack, "params", []))
        if params:
            pf.params = params
            pf.var_decls = [d for d in pf.var_decls
                            if d.split()[1].rstrip(";[]") not in params]
        pf.ir = ir
        pf.engine = "ir"
        if getattr(ir, "unsupported", None):
            pf.unsupported = len(ir.unsupported)

    INPUT_FUNCS = {"read", "gets", "scanf", "fgets", "strcpy", "strncpy",
                   "memcpy", "recv", "strcat", "sprintf", "sscanf"}

    @classmethod
    def _call_exprs(cls, e, out):
        if not isinstance(e, tuple):
            return
        if e[0] == "call":
            out.append(e)
            for a in e[2]:
                cls._call_exprs(a, out)
        elif e[0] == "bin":
            cls._call_exprs(e[2], out)
            cls._call_exprs(e[3], out)
        elif e[0] == "un":
            cls._call_exprs(e[2], out)
        elif e[0] == "mem":
            cls._call_exprs(e[1], out)
            if e[2] is not None:
                cls._call_exprs(e[2], out)

    def _decls(self, ir):
        stack = ir.stack
        buffer_names = set()
        # buffers: stack slots handed to input functions (calls may be inlined
        # into conditions or assignments, so scan every statement expression)
        for block in ir.blocks.values():
            for st in block.stmts:
                if st[0] == "call":
                    fname = st[1][:-4] if st[1].endswith("@plt") else st[1]
                    if fname in self.INPUT_FUNCS:
                        for arg in st[2]:
                            if arg[0] == "var":
                                buffer_names.add(arg[1])
                    for arg in st[2]:
                        self._call_exprs(arg, [])
                elif st[0] == "assign":
                    self._scan_call_buffers(st[2], buffer_names)
                elif st[0] == "store":
                    self._scan_call_buffers(st[2], buffer_names)
            term = block.term
            if term and len(term) > 1 and isinstance(term[1], tuple):
                self._scan_call_buffers(term[1], buffer_names)
        buffer_names |= set(getattr(ir, "address_taken", set()))
        decls = []
        off_of = {name: off for off, name in stack.slots.items()}
        for name in stack.order:
            if name in getattr(ir, "canary_vars", set()):
                continue
            word = "uint64_t" if getattr(self.elf, "bits", 64) == 64 else "uint32_t"
            if name in buffer_names:
                size = max(8, abs(off_of.get(name, 0)) or 0x40)
                decls.append(f"char {name}[{size}];")
            else:
                decls.append(f"{word} {name};")
        return decls

    def _scan_call_buffers(self, expr, buffer_names):
        calls = []
        self._call_exprs(expr, calls)
        for call in calls:
            fname = call[1][:-4] if call[1].endswith("@plt") else call[1]
            if fname in self.INPUT_FUNCS:
                for arg in call[2]:
                    if arg[0] == "var":
                        buffer_names.add(arg[1])

    # ------------------------------------------------------------------
    # legacy linear lifter: kept as a safety net (and for odd instruction
    # streams the structurer cannot model)
    def _lift_legacy(self, insns, pf, base):
        var_id = 0
        vars_ = {}
        rbp_off = {}
        arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        pending_args = {}
        indent = 0
        last_cmp = None

        def newvar(slot):
            nonlocal var_id
            if slot not in vars_:
                vars_[slot] = f"v{var_id}"
                rbp_off[vars_[slot]] = slot
                var_id += 1
            return vars_[slot]

        for ins in insns:
            if ins.mnem == "push" and ins.ops == ["rbp"]:
                continue
            if ins.mnem == "mov" and len(ins.ops) == 2 and ins.ops == ["rbp", "rsp"]:
                continue
            if ins.mnem in ("leave",):
                continue
            if ins.mnem == "pop" and ins.ops == ["rbp"]:
                continue
            for opnd in ins.ops:
                if "[rbp" in opnd:
                    newvar(opnd)
            if ins.mnem == "lea" and len(ins.ops) == 2:
                dst, src = ins.ops
                if "rip" in src:
                    tgt = None
                    if "=>" in src:
                        try:
                            tgt = int(src.split("=>")[1].strip().split()[0], 16)
                        except (ValueError, IndexError):
                            tgt = None
                    if tgt is None:
                        try:
                            disp = src.strip("[]").split("rip")[1]
                            tgt = ins.addr + ins.size + (int(disp, 16) if disp else 0)
                        except (ValueError, IndexError):
                            tgt = None
                    if tgt is not None and tgt in self.strmap:
                        pf.string_refs[ins.addr] = self.strmap[tgt]
                        pending_args[dst] = f'"{self.strmap[tgt]}"'
                        continue
                if "[rbp" in src:
                    pending_args[dst] = newvar(src)
                    continue
            if ins.mnem == "mov" and len(ins.ops) == 2:
                dst, src = ins.ops
                if dst in arg_regs:
                    if src in pending_args:
                        pending_args[dst] = pending_args[src]
                    else:
                        pending_args[dst] = src
                    continue
                if src in pending_args and dst.startswith("[rbp"):
                    newvar(dst)
                    pf.lines.append((indent, f"{vars_[dst]} = {pending_args[src]};"))
                    continue
                if src in pending_args and dst in arg_regs:
                    pending_args[dst] = pending_args[src]
                    continue
            if ins.mnem == "xor" and len(ins.ops) == 2 and ins.ops[0] == ins.ops[1]:
                r = ins.ops[0]
                if r in arg_regs:
                    pending_args[r] = "0"
                pf.lines.append((indent, f"{r} = 0;"))
                continue
            if ins.mnem == "cmp" and len(ins.ops) == 2:
                last_cmp = ins.ops
                pf.lines.append((indent, f"/* if ({ins.ops[0]} {'==' if ins.ops[1]=='0x0' else '!='} {ins.ops[1]}) ... */"))
                continue
            if ins.is_call:
                fname = self._fname(ins.target())
                pf.calls.append(fname)
                args = [pending_args.get(r, r) for r in arg_regs]
                n = 0
                for i, a in enumerate(args):
                    if not (a in arg_regs or a in REG64):
                        n = i + 1
                pf.lines.append((indent, f"{fname}({', '.join(args[:max(n,0)])});"))
                if fname in ("system", "execve") and any("/bin/sh" in a for a in args[:1]):
                    pf.effects.append(("backdoor_shell", pf.string_refs.get(ins.addr, "/bin/sh")))
                pending_args = {}
                continue
            if ins.mnem == "syscall":
                pf.lines.append((indent, "syscall();"))
                continue
            if ins.is_jcc:
                indent = max(0, indent - 1)
                pf.lines.append((indent, "}"))
                continue
            if ins.is_jmp:
                continue
            if ins.mnem == "ret":
                pf.lines.append((indent, "return;"))
                continue
            pf.lines.append((indent, f"// {ins.mnem} {', '.join(ins.ops)}".rstrip()))

        def slot_to_int(slot):
            s = slot.strip("[] ")
            try:
                if s.startswith("rbp"):
                    return int(s[3:] or "0", 16)
            except ValueError:
                pass
            return 8
        pf.var_decls = [f"char {vars_[s]}[{abs(slot_to_int(s)) or 8}];" for s in vars_]

    # ------------------------------------------------------------------
    def render(self, pf, ansi=False):
        """plain C-like text (ansi=True adds terminal syntax colours)"""
        body = []
        header = f"// {pf.name} @ {pf.addr:#x}  (decompiled by AntPwn/guaidao2)"
        if getattr(pf, "engine", "ir") == "legacy":
            header += "  [legacy linear lifter]"
        elif getattr(pf, "unsupported", 0):
            header += f"  [{pf.unsupported} unsupported instruction(s)]"
        body.append(header)
        word = "uint64_t" if getattr(self.elf, "bits", 64) == 64 else "uint32_t"
        params = ", ".join(f"{word} {p}" for p in getattr(pf, "params", []))
        body.append(f"void {pf.name}({params or 'void'}) {{")
        for d in pf.var_decls:
            body.append("    " + d)
        if pf.var_decls:
            body.append("")
        for ind, txt in pf.lines:
            if ind < 0:
                body.append(txt)
            else:
                body.append("    " * (ind + 1) + txt)
        body.append("}")
        text = "\n".join(body)
        if ansi and color.enabled():
            return color.highlight_c(text)
        return text

    def render_ansi(self, pf):
        return self.render(pf, ansi=True)
