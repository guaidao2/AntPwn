"""AntPwn IR: lift x86-64 to a tiny P-code-like representation.

Pure standard library.  This is the analysis backend for the decompiler:
expression trees, basic blocks, CFG dominators/post-dominators, natural loops,
symbolic register environment (copy/constant propagation), and stack-slot
recovery.  It is inspired by the Ghidra decompiler's P-code/SSA pipeline, but
implemented from scratch for the AntPwn disassembler subset.
"""
from .disasm import REG64, REG8, REG16, REG32, REG8_32, REG16_32

CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
ALIAS = {}
for _r in REG64:
    ALIAS[_r] = _r
for _i, _r in enumerate(REG8):
    ALIAS[_r] = REG64[_i]
for _i, _r in enumerate(REG16):
    ALIAS[_r] = REG64[_i]
# 32-bit names stay in their own namespace (i386 binaries are analysed separately)
ALIAS32 = {}
for _r in REG32:
    ALIAS32[_r] = _r
for _i, _r in enumerate(REG8_32):
    ALIAS32[_r] = REG32[_i]
for _i, _r in enumerate(REG16_32):
    ALIAS32[_r] = REG32[_i]

CMP_FOR_JCC = {
    "e": "==", "ne": "!=", "l": "<", "le": "<=", "g": ">", "ge": ">=",
    "b": "<u", "be": "<=u", "a": ">u", "ae": ">=u",
    "s": "<0", "ns": ">=0", "o": "ovf", "no": "!ovf",
}
UNSIGNED = {"<u", "<=u", ">u", ">=u"}


# ---------------------------------------------------------------- expressions
def const(v):
    return ("const", v & 0xFFFFFFFFFFFFFFFF)


def reg(name):
    return ("reg", ALIAS.get(name, name))


def var(name):
    return ("var", name)


def string(text):
    return ("str", text)


def binop(op, a, b):
    """binary expression with constant folding + algebraic identities"""
    if a[0] == "const" and b[0] == "const":
        x, y = a[1], b[1]
        try:
            if op == "+":
                return const(x + y)
            if op == "-":
                return const(x - y)
            if op == "*":
                return const(x * y)
            if op == "&":
                return const(x & y)
            if op == "|":
                return const(x | y)
            if op == "^":
                return const(x ^ y)
            if op == "<<":
                return const(x << (y & 63))
            if op == ">>":
                return const(x >> (y & 63))
        except Exception:
            pass
    if op in ("+", "-", "|", "^"):
        if b[0] == "const" and b[1] == 0:
            return a
        if a[0] == "const" and a[1] == 0 and op == "+":
            return b
    if op == "*":
        if b[0] == "const" and b[1] == 1:
            return a
        if a[0] == "const" and a[1] == 1:
            return b
        if (a[0] == "const" and a[1] == 0) or (b[0] == "const" and b[1] == 0):
            return const(0)
    if op == "&":
        if b[0] == "const" and b[1] == 0xFFFFFFFFFFFFFFFF:
            return a
        if a[0] == "const" and a[1] == 0xFFFFFFFFFFFFFFFF:
            return b
    if a == b:
        if op == "-":
            return const(0)
        if op in ("^",):
            return const(0)
        if op in ("==", "<=", ">=", "<=u", ">=u"):
            return const(1)
        if op in ("!=", "<", ">", "<u", ">u"):
            return const(0)
        if op == "&":
            return a
        if op == "|":
            return a
    return ("bin", op, a, b)


def unop(op, a):
    if a[0] == "const":
        if op == "-":
            return const(-a[1])
        if op == "~":
            return const(~a[1])
        if op == "!":
            return const(0 if a[1] else 1)
    if op == "!" and a[0] == "un" and a[1] == "!":
        return a[2]
    return ("un", op, a)


def is_const(e, v=None):
    return e[0] == "const" and (v is None or e[1] == v)


def expr_vars(e, out):
    if e[0] == "var":
        out.add(e[1])
    elif e[0] in ("bin",):
        expr_vars(e[2], out)
        expr_vars(e[3], out)
    elif e[0] in ("un",):
        expr_vars(e[2], out)
    elif e[0] in ("mem",):
        expr_vars(e[1], out)
        if e[2] is not None:
            expr_vars(e[2], out)
    elif e[0] == "call":
        for a in e[2]:
            expr_vars(a, out)


def invert(e):
    if e[0] == "un" and e[1] == "!":
        return e[2]
    if e[0] == "bin" and e[1] in ("==", "!=", "<", "<=", ">", ">=",
                                 "<u", "<=u", ">u", ">=u"):
        inv = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=",
               ">=": "<", "<u": ">=u", "<=u": ">u", ">u": "<=u", ">=u": "<u"}
        return ("bin", inv[e[1]], e[2], e[3])
    return unop("!", e)


def render(e):
    """precedence-aware C expression printer"""
    op = e[0]
    if op == "const":
        v = e[1]
        return f"{v:#x}" if v else "0"
    if op == "reg":
        return e[1]
    if op == "var":
        return e[1]
    if op == "str":
        text = e[1].replace("\\", "\\\\").replace('"', '\\"')
        return f'"{text}"'
    if op == "addr":
        return f"g_{e[1]:x}"
    if op == "canary":
        return "__stack_chk_guard"
    if op == "call":
        return f"{e[1]}({', '.join(render(a) for a in e[2])})"
    if op == "mem":
        base, index = e[1], e[2]
        if base[0] == "addr" or base[0] == "str":
            ptr = render(base)
        else:
            ptr = _wrap(base, 7)
        return f"*{ptr}" if index is None else f"({ptr})[{render(index)}]"
    if op == "bin":
        prec = {"|": 1, "^": 2, "&": 3, "==": 4, "!=": 4,
                "<": 5, "<=": 5, ">": 5, ">=": 5,
                "<u": 5, "<=u": 5, ">u": 5, ">=u": 5,
                "<<" : 6, ">>": 6, "+": 7, "-": 7, "*": 8, "/": 8}
        p = prec.get(e[1], 7)
        left, right = _wrap(e[2], p), _wrap(e[3], p + 1)
        return f"{left} {_BIN_SYM.get(e[1], e[1])} {right}"
    if op == "un":
        return f"{e[1]}{_wrap(e[2], 9)}"
    return "?"


_BIN_SYM = {"<u": "<", "<=u": "<=", ">u": ">", ">=u": ">="}


def _wrap(e, parent):
    s = render(e)
    if e[0] in ("const", "reg", "var", "str"):
        return s
    ops = {"|": 1, "^": 2, "&": 3, "==": 4, "!=": 4, "<": 5, "<=": 5,
           ">": 5, ">=": 5, "<u": 5, "<=u": 5, ">u": 5, ">=u": 5,
           "<<": 6, ">>": 6, "+": 7, "-": 7, "*": 8, "/": 8}
    p = ops.get(e[1], 7) if e[0] == "bin" else 9
    return f"({s})" if p < parent else s


# ---------------------------------------------------------------- memory / stack
class StackModel:
    """stack slots recovered from [rbp-N]/[rsp+N] operands"""

    def __init__(self):
        self.slots = {}          # offset -> name
        self.size = {}           # name -> bytes
        self.order = []
        self.params = []         # cdecl argument names (32-bit [ebp+8]...)
        self.bits = 64
        self.fp_frame = False    # function really set up ebp/rbp as a frame pointer

    def arg_slot(self, off, size=8):
        name = f"arg{(off - 8) // 4}"
        if name not in self.params:
            self.params.append(name)
        self.size[name] = max(self.size.get(name) or 0, size)
        return name

    def slot(self, off, size=8):
        if off not in self.slots:
            name = f"v{len(self.slots)}"
            self.slots[off] = name
            self.size[name] = size
            self.order.append(name)
        name = self.slots[off]
        self.size[name] = max(self.size.get(name) or 0, size)
        return name

    def decls(self):
        out = []
        for name in self.order:
            size = self.size.get(name) or 8
            if size >= 8 and size % 8 == 0:
                out.append(f"char {name}[{size}];")
            else:
                out.append(f"char {name}[{max(8, size)}];")
        return out


_MEM_RE = None


def parse_mem(op, stack, base):
    """memory operand -> expression tree.

    Handles stack slots ([rbp-N]), globals ([0x404080]) and general pointer
    expressions ([rax], [rax*8+0x404080], [rcx+rax]); the latter become
    ("mem", base_expr, index_expr_or_None, disp).
    """
    global _MEM_RE
    import re
    if _MEM_RE is None:
        _MEM_RE = re.compile(
            r"^(-?0x[0-9a-f]+|[a-z0-9]+)(?:\+([a-z0-9]+)\*(\d+))?(([+-])0x([0-9a-f]+))?$")
    op = op.strip()
    if not op.startswith("["):
        return None
    inner = op[1:op.index("]")]
    if "=>" in op:
        try:
            tgt = int(op.split("=>")[1].strip().split()[0], 16)
        except (ValueError, IndexError):
            tgt = None
        if tgt is not None:
            return ("addr", tgt)      # absolute address (string/global)
    if inner.startswith(("fs:", "gs:")):
        # x86-64 TLS canary is fs:0x28, i386 uses gs:0x14
        return ("canary",)
    if inner.startswith("rip"):
        return ("addr", 0)
    if any(r in inner for r in ("rbp", "rsp", "ebp", "esp")):
        base_reg = next(r for r in ("rbp", "rsp", "ebp", "esp") if r in inner)
        rest = inner.replace(base_reg, "").replace(" ", "")
        if "+" in rest and "*" in rest:
            # [rbp+rax*8-0x30]
            parts = rest
            idx = None
            disp = 0
            import re
            m = re.match(r"\+([a-z0-9]+)\*(\d+)([+-]0x[0-9a-f]+)?", parts)
            if m:
                idx = ("reg", ALIAS.get(m.group(1),
                                       ALIAS32.get(m.group(1), m.group(1))))
                disp = int(m.group(3) or "0", 0) if m.group(3) else 0
            else:
                try:
                    disp = int(parts or "0", 0)
                except ValueError:
                    disp = 0
            name = stack.slot(disp, 8)
            return ("mem", var(name), idx)
        try:
            disp = int(rest or "0", 0)
        except ValueError:
            disp = 0
        if stack.bits == 32 and stack.fp_frame \
                and base_reg in ("ebp", "rbp") and disp >= 8 and disp % 4 == 0:
            return var(stack.arg_slot(disp))
        name = stack.slot(disp, 8)
        return var(name)
    if inner.startswith("0x") and "*" not in inner and "+" not in inner \
            and "-" not in inner:
        try:
            return ("addr", int(inner, 16))
        except ValueError:
            return None
    # general pointer expression: [reg], [reg*scale], [reg+disp], [reg+reg*scale+disp]
    m = _MEM_RE.match(inner.replace(" ", ""))
    if not m:
        return None
    base_name, idx_name, scale, _sign, _s, disp_s = m.groups()
    base_expr = None
    if base_name in ALIAS or base_name in ALIAS32:
        base_expr = ("reg", ALIAS.get(base_name, ALIAS32.get(base_name)))
    else:
        try:
            base_expr = ("addr", int(base_name, 16))
        except ValueError:
            return None
    disp = int(disp_s, 16) if disp_s else 0
    if _sign == "-":
        disp = -disp
    if disp:
        base_expr = binop("+", base_expr, const(disp))
    index_expr = None
    if idx_name and (idx_name in ALIAS or idx_name in ALIAS32):
        index_expr = binop("*", ("reg", ALIAS.get(idx_name,
                                                  ALIAS32.get(idx_name))),
                           const(int(scale)))
    return ("mem", base_expr, index_expr)


# ---------------------------------------------------------------- statements
def assign(dst, expr):
    return ("assign", dst, expr)


def store(dst, expr):
    return ("store", dst, expr)


def call(fname, args):
    return ("call", fname, tuple(args))


def branch(cond, tgt, ftgt):
    return ("branch", cond, tgt, ftgt)


def goto(tgt):
    return ("goto", tgt)


def ret_(expr):
    return ("ret", expr)


class Block:
    __slots__ = ("addr", "insns", "stmts", "term", "succs", "env_out",
                 "cond", "targets")

    def __init__(self, addr):
        self.addr = addr
        self.insns = []
        self.stmts = []
        self.term = None          # ("jcc", cond, tgt) / ("jmp", tgt) / ("ret", e) / None
        self.succs = []
        self.env_out = {}
        self.cond = None
        self.targets = []


class FunctionIR:
    def __init__(self, name, entry):
        self.name = name
        self.entry = entry
        self.blocks = {}          # addr -> Block
        self.order = []           # addresses in linear order
        self.stack = StackModel()
        self.strings = {}         # addr -> text
        self.calls = []
        self.effects = []
        self.env_calls = {}
        self.dom = {}
        self.pdom = {}
        self.loops = []           # (header, latch)
        self.call_info = {}       # block addr -> [args]
        self.canary_vars = set()
        self.address_taken = set()   # stack var whose address escapes (buffer)
        self.unsupported = []     # lifted-but-unmodelled instructions

    def block_at(self, addr):
        return self.blocks.get(addr)

    # ---------------- CFG ----------------
    def build_cfg(self):
        for addr in self.order:
            b = self.blocks[addr]
            term = b.term
            succ = []
            if term is None:
                nxt = self.next_block(addr)
                if nxt is not None:
                    succ.append(nxt)
            elif term[0] == "jcc":
                if term[2] in self.blocks:
                    succ.append(term[2])
                nxt = self.next_block(addr)
                if nxt is not None:
                    succ.append(nxt)
            elif term[0] == "jmp":
                if term[1] in self.blocks:
                    succ.append(term[1])
            b.succs = succ
        # predecessors
        self.preds = {a: [] for a in self.blocks}
        for a in self.order:
            for s in self.blocks[a].succs:
                self.preds[s].append(a)

    def next_block(self, addr):
        try:
            i = self.order.index(addr)
        except ValueError:
            return None
        return self.order[i + 1] if i + 1 < len(self.order) else None

    def compute_dominators(self):
        addrs = self.order
        all_ = set(addrs)
        dom = {a: set(all_) for a in addrs}
        dom[self.entry] = {self.entry}
        changed = True
        while changed:
            changed = False
            for a in addrs:
                if a == self.entry:
                    continue
                ps = self.preds.get(a) or []
                if not ps:
                    new = {a}
                else:
                    new = {a} | set.intersection(*(dom[p] for p in ps))
                if new != dom[a]:
                    dom[a] = new
                    changed = True
        self.dom = dom

    def compute_postdominators(self):
        addrs = self.order
        all_ = set(addrs)
        exits = [a for a in addrs if not self.blocks[a].succs]
        pdom = {a: set(all_) for a in addrs}
        for e in exits:
            pdom[e] = {e}
        changed = True
        while changed:
            changed = False
            for a in reversed(addrs):
                if a in exits:
                    continue
                ss = self.blocks[a].succs
                if not ss:
                    new = {a}
                else:
                    new = {a} | set.intersection(*(pdom[s] for s in ss))
                if new != pdom[a]:
                    pdom[a] = new
                    changed = True
        self.pdom = pdom

    def immediate_postdom(self, a):
        cands = self.pdom.get(a, set()) - {a}
        if not cands:
            return None
        best = None
        for c in cands:
            # c is the immediate post-dominator if no other candidate is
            # post-dominated by it
            if all(c == o or o in self.pdom.get(c, set()) for o in cands):
                best = c
                break
        return best if best is not None else (sorted(cands)[0])

    def find_loops(self):
        loops = []
        for a in self.order:
            for s in self.blocks[a].succs:
                if s in self.dom.get(a, set()) and s != a:
                    body = {s, a}
                    stack = [a]
                    while stack:
                        x = stack.pop()
                        for p in self.preds.get(x, []):
                            if p not in body and s in self.dom.get(p, set()):
                                body.add(p)
                                stack.append(p)
                    loops.append((s, a, body))
        self.loops = loops
        return loops


# ---------------------------------------------------------------- lifter
class Lifter:
    """lift instructions to statements, with symbolic env + dataflow"""

    def __init__(self, elf, ir, base):
        self.elf = elf
        self.ir = ir
        self.base = base
        self.plt = elf.plt_map()
        self.functions = {s.value: s.name for s in elf.functions()}
        self.frame_off = 0          # bytes subtracted from rsp since entry
        self.bits = getattr(elf, "bits", 64)
        self.alias = ALIAS if self.bits == 64 else ALIAS32
        self.arg_regs = ARG_REGS if self.bits == 64 else []
        self.push_stack = []
        self.ir.stack.bits = self.bits

    # operand -> expression
    def _sp_slot(self, op, env):
        """[rsp+N] / rsp itself -> frame slot when we track a frame pointer-less frame"""
        if env is None:
            return None
        sp_key = "rsp" if "rsp" in env else "esp"
        if env.get(sp_key, (None,))[0] != "sp":
            return None
        frame = env[sp_key][1]
        if op in ("rsp", "esp"):
            return var(self.ir.stack.slot(frame))
        if not op.startswith("["):
            return None
        inner = op[1:op.index("]")].replace(" ", "")
        if not (inner.startswith("rsp") or inner.startswith("esp")):
            return None
        rest = inner[3:]
        if rest.startswith("+"):
            disp = int(rest[1:], 16) if rest[1:].startswith("0x") else int(rest[1:])
        elif rest.startswith("-"):
            disp = -(int(rest[1:], 16) if rest[1:].startswith("0x") else int(rest[1:]))
        elif rest == "":
            disp = 0
        else:
            return None
        return var(self.ir.stack.slot(frame - disp))

    def operand(self, op, env=None):
        stack = self.ir.stack
        slot = self._sp_slot(op, env)
        if slot is not None:
            return slot
        e = parse_mem(op, stack, self.base)
        if e is not None:
            if env is not None and e[0] == "var" and \
                    e[1] in getattr(self.ir, "canary_vars", set()):
                return ("canary",)
            if e[0] == "addr":
                addr = e[1]
                if addr in self.strmap:
                    self.ir.strings[addr] = self.strmap[addr]
                    return string(self.strmap[addr])
                return const(addr)
            return e
        if op in self.alias:
            name = self.alias[op]
            if env is not None and name in env:
                return env[name]
            return reg(name)
        try:
            return const(int(op, 16))
        except ValueError:
            return None

    def lift(self, insns, strmap):
        self.strmap = strmap
        ir = self.ir
        # split into basic blocks (keep nops: a branch may target a nop)
        leaders = {insns[0].addr} if insns else set()
        for idx, ins in enumerate(insns):
            if ins.is_jcc or ins.is_jmp or ins.is_ret:
                if idx + 1 < len(insns):
                    leaders.add(insns[idx + 1].addr)
            if (ins.is_jcc or ins.is_jmp) and ins.target() is not None:
                leaders.add(ins.target())
        leaders = sorted(a for a in leaders if any(i.addr == a for i in insns))
        if not leaders:
            return
        cur = None
        for ins in insns:
            if ins.addr in leaders:
                cur = Block(ins.addr)
                ir.blocks[ins.addr] = cur
                ir.order.append(ins.addr)
            if cur is not None:
                cur.insns.append(ins)
        # terminators must exist before the CFG is built; lift once with an
        # empty env just to fill block.term, then rebuild the CFG.
        for addr in ir.order:
            self.lift_block(ir.blocks[addr], {}, collect=False)
        ir.build_cfg()
        ir.compute_dominators()
        ir.compute_postdominators()
        ir.find_loops()
        # forward dataflow to get a stable entry environment per block
        entry_env = {ir.order[0]: {}} if ir.order else {}
        for _ in range(6):
            changed = False
            for addr in ir.order:
                env = dict(entry_env.get(addr, {}))
                self.lift_block(ir.blocks[addr], env, collect=True)
                out = ir.blocks[addr].env_out
                for s in ir.blocks[addr].succs:
                    old = entry_env.get(s, {})
                    merged = self.merge_env(old, out) if old else dict(out)
                    if merged != old:
                        entry_env[s] = merged
                        changed = True
            if not changed:
                break
        # final lift with statements (terms do not change, env may)
        for addr in ir.order:
            self.lift_block(ir.blocks[addr], dict(entry_env.get(addr, {})),
                            collect=True)

    @staticmethod
    def merge_env(a, b):
        out = {}
        for k, v in a.items():
            if k in b and b[k] == v:
                out[k] = v
        return out

    def fname(self, tgt):
        if tgt is None:
            return "func_ptr"
        if tgt in self.plt:
            return self.plt[tgt] + "@plt"
        if tgt in self.functions:
            return self.functions[tgt]
        return f"sub_{tgt:x}"

    def lift_block(self, block, env, collect=False):
        stmts = []
        self._flag = None
        # cdecl argument pushes must not leak across basic blocks
        self.push_stack = []
        for ins in block.insns:
            try:
                self.lift_insn(ins, env, stmts, collect)
            except Exception:
                if collect:
                    stmts.append(("comment", f"{ins.mnem} {', '.join(ins.ops)}"))
        flags = self._flag
        block.stmts = stmts
        # terminator
        last = block.insns[-1] if block.insns else None
        if last is None:
            block.term = None
        elif last.is_ret:
            ret_reg = "rax" if self.bits == 64 else "eax"
            block.term = ("ret", env.get(ret_reg, reg(ret_reg)))
        elif last.is_jmp:
            block.term = ("jmp", last.target())
        elif last.is_jcc:
            block.term = ("jcc", self._jcc_expr(last, flags), last.target())
        else:
            block.term = None
        block.env_out = dict(env)

    def _jcc_expr(self, ins, flags):
        name = ins.mnem[1:] if ins.mnem.startswith("j") else ins.mnem
        op = CMP_FOR_JCC.get(name)
        if flags is None or op is None:
            return reg("flags")
        if flags[0] == "test":
            lhs, rhs = flags[1], flags[2]
            z = binop("&", lhs, rhs)
            return binop("!=", z, const(0)) if op == "!=" else binop("==", z, const(0))
        lhs, rhs = flags[1], flags[2]
        kind = flags[0]
        if kind in ("add", "and", "or", "xor"):
            if op == "!=":
                if kind == "add":
                    return binop("!=", lhs, binop("-", const(0), rhs))
                return binop("!=", binop(kind, lhs, rhs), const(0))
            if op == "==":
                if kind == "add":
                    return binop("==", lhs, binop("-", const(0), rhs))
                return binop("==", binop(kind, lhs, rhs), const(0))
            return reg("flags")
        if op == "!=":
            return binop("!=", lhs, rhs)
        if op == "==":
            return binop("==", lhs, rhs)
        return ("bin", op, lhs, rhs)

    # ---------------- instruction lifting ----------------
    def lift_insn(self, ins, env, stmts, collect):
        m, ops = ins.mnem, ins.ops
        def A(i):
            return self.operand(ops[i], env) if i < len(ops) else None
        def setreg(name, expr):
            env[self.alias.get(name, name)] = expr

        # prologue / epilogue noise
        if m == "push" and ops[:1] in (["rbp"], ["ebp"]):
            return
        if m == "mov" and ops in (["rbp", "rsp"], ["ebp", "esp"]):
            self.ir.stack.fp_frame = True
            return
        if m == "leave" or (m == "pop" and ops[:1] in (["rbp"], ["ebp"])):
            return
        if m in ("nop", "endbr64", "endbr", "ud2", "int3", "bad",
                 "cwde", "cdqe"):
            return
        if m == "inc" or m == "dec":
            tgt = A(0)
            if tgt is not None and tgt[0] == "reg":
                val = binop("+", tgt, const(1)) if m == "inc" \
                    else binop("-", tgt, const(1))
                setreg(tgt[1], val)
            elif tgt is not None:
                val = binop("+", tgt, const(1)) if m == "inc" \
                    else binop("-", tgt, const(1))
                stmts.append(store(tgt, val))
            return
        if m in ("arpl", "endbr32", "endbr64"):
            return
        if m == "push":
            e = A(0)
            if self.bits == 32 and self.ir.stack.fp_frame \
                    and e is not None and e[0] == "reg" \
                    and e[1] in ("ebx", "esi", "edi", "ebp"):
                # callee-saved register spill, not a cdecl argument
                return
            if e is not None:
                self.push_stack.append(e)
            return
        if m == "pop":
            if self.push_stack:
                self.push_stack.pop()
            return
        if m == "movups":
            return

        if m in ("sub", "add") and ops[0] in ("rsp", "esp") and len(ops) == 2:
            try:
                imm = int(ops[1], 16)
            except ValueError:
                imm = None
            if imm is not None:
                self.frame_off += imm if m == "sub" else -imm
                env.setdefault("rsp", ("sp", 0))
                env["rsp"] = ("sp", self.frame_off)
                if ops[0] == "esp":
                    env["esp"] = ("sp", self.frame_off)
                return
        if m == "mov" and len(ops) == 2:
            dst, src = ops
            expr = A(1)
            if expr is None:
                return
            if dst in self.alias:
                setreg(dst, expr)
            elif dst.startswith("["):
                tgt = self.operand(dst)
                if tgt is not None:
                    canary_slots = getattr(self.ir, "canary_vars", set())
                    if tgt[0] == "var" and tgt[1] in canary_slots:
                        pass                     # writing the stack guard: hide
                    elif expr[0] == "canary" and tgt[0] == "var":
                        self.ir.canary_vars.add(tgt[1])   # hidden guard slot
                    else:
                        stmts.append(store(tgt, expr))
            return
        if m == "lea" and len(ops) == 2:
            expr = A(1)
            if expr is not None and ops[0] in self.alias:
                if expr[0] == "var":
                    self.ir.address_taken.add(expr[1])
                setreg(ops[0], expr)
            return
        if m in ("add", "sub", "and", "or", "xor") and len(ops) == 2:
            dst, src = ops
            a, b = A(0), A(1)
            if a is None or b is None:
                return
            op = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^"}[m]
            self._flag = (m, a, b)
            if a[0] == "reg" and b[0] == "reg" and a[1] == b[1] and m == "xor":
                val = const(0)
            else:
                val = binop(op, a, b)
            if dst in self.alias:
                setreg(dst, val)
            else:
                tgt = A(0)
                if tgt is not None:
                    stmts.append(store(tgt, val))
            return
        if m in ("inc", "dec") and len(ops) == 1:
            a = A(0)
            if a is not None:
                val = binop("+" if m == "inc" else "-", a, const(1))
                if ops[0] in self.alias:
                    setreg(ops[0], val)
                else:
                    tgt = A(0)
                    if tgt is not None:
                        stmts.append(store(tgt, val))
            return
        if m in ("shl", "sal", "shr", "sar") and len(ops) == 2:
            a, b = A(0), A(1)
            if a is None or b is None:
                return
            op = "<<" if m in ("shl", "sal") else ">>"
            val = binop(op, a, b)
            if ops[0] in self.alias:
                setreg(ops[0], val)
            return
        if m in ("movzx", "movsx", "movsxd", "setne", "sete", "setl", "setg",
                  "setle", "setge", "setb", "seta", "setbe", "setae",
                  "sets", "setns") and len(ops) == 2:
            a = A(1)
            if a is not None and ops[0] in self.alias:
                setreg(ops[0], a)
            return
        if m.startswith("set") and len(ops) == 1 and self._flag is not None:
            kind, fa, fb = self._flag
            cc = m[3:]
            cond = self._jcc_expr(Insn(ins.addr, ins.size, "j" + cc, [], b""), self._flag)
            if ops[0] in self.alias:
                setreg(ops[0], cond)
            return
        if m in ("cmp", "test"):
            fa = self.operand(ops[0], env) if len(ops) > 0 else None
            fb = self.operand(ops[1], env) if len(ops) > 1 else None
            if fa is not None and fb is not None:
                self._flag = (m, fa, fb)
            return
        if m in ("cdq", "cqo"):
            setreg("rdx", binop(">>", env.get("rax", reg("rax")), const(63)))
            return
        if m == "call":
            tgt = ins.target()
            fname = self.fname(tgt)
            args = []
            if self.bits == 32:
                args = list(reversed(self.push_stack))
                self.push_stack.clear()
            else:
                for r in ARG_REGS:
                    e = env.get(r)
                    if e is None:
                        args.append(reg(r))
                    else:
                        args.append(e)
            # unknown registers past the first known argument are noise: cut
            # there, trim trailing regs and duplicated trailing args
            cut = None
            for i in range(1, len(args)):
                if args[i][0] == "reg" and args[i][1] in ARG_REGS:
                    cut = i
                    break
            if cut is not None:
                args = args[:cut]
            while args and args[-1][0] == "reg" and args[-1][1] in ARG_REGS:
                args.pop()
            while len(args) >= 2 and args[-1] == args[-2]:
                args.pop()
            call_expr = ("call", fname, tuple(args))
            if collect:
                stmts.append(call(fname, args))
                self.ir.calls.append(fname)
                base = fname.split("@")[0]
                for pref in ("__libc_", "_IO_", "__GI_", "__isoc99_"):
                    if base.startswith(pref):
                        base = base[len(pref):]
                        break
                if base in ("system", "execve") and args and args[0][0] == "str":
                    self.ir.effects.append(("backdoor_shell", args[0][1]))
            for r in (CALLER_SAVED if self.bits == 64 else
                      {"eax", "ecx", "edx"}):
                env[r] = reg(r)
            env["rax" if self.bits == 64 else "eax"] = call_expr
            return
        if m == "syscall" or m == "sysenter" or (m == "int" and ops[:1] == ["0x80"]):
            if collect:
                stmts.append(("syscall",))
            ret_reg = "eax" if self.bits == 32 else "rax"
            env[ret_reg] = ("call", "syscall", ())
            return
        if m in ("jmp", "jcc") or ins.is_jmp or ins.is_jcc:
            return
        if m == "ret":
            return
        if collect and not ins.is_jcc and not ins.is_jmp:
            stmts.append(("comment", f"{m} {', '.join(ops)}".strip()))
            self.ir.unsupported.append(f"{m} {', '.join(ops)}".strip())
