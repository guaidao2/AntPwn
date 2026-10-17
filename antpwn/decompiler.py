"""AntPwn decompiler: lift disassembly to C-like pseudo-code
伪代码还原: 从指令流恢复 函数调用/局部变量/控制流/if-else/while 结构
"""
from .disasm import Disasm, REG64


class PseudoFunc:
    def __init__(self, name, addr, size):
        self.name, self.addr, self.size = name, addr, size
        self.lines = []          # (indent, text)
        self.calls = []          # called function names
        self.stack_vars = {}     # rsp/rbp offsets -> var names
        self.string_refs = {}    # lea targets -> strings
        self.effects = []        # interesting side effects


class Decompiler:
    def __init__(self, elf, strings=None):
        self.elf = elf
        self.strmap = {}
        for va, s in (strings or elf.strings()):
            self.strmap.setdefault(va, s)

    def function(self, sym):
        code = self.elf.read(sym.value, sym.size or 0x200)
        if not code:
            return None
        dis = Disasm(code, sym.value)
        insns = dis.recursive(len(code), [0])
        pf = PseudoFunc(sym.name, sym.value, sym.size)
        self._lift(insns, pf, sym.value)
        return pf

    # ------------------------------------------------------------------
    def _lift(self, insns, pf, base):
        var_id = 0
        vars_ = {}          # "rbp-0x20" -> v0
        rbp_off = {}
        # pass 1: find stack var references & calls
        cur_call = None
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
            txt = f"{ins.mnem} {', '.join(ins.ops)}".strip()
            # --- push rbp; mov rbp,rsp -> function prologue (skip) ---
            if ins.mnem == "push" and ins.ops == ["rbp"]:
                continue
            if ins.mnem == "mov" and len(ins.ops) == 2 and ins.ops == ["rbp", "rsp"]:
                continue
            # --- leave/ret epilogue ---
            if ins.mnem in ("leave",):
                continue
            if ins.mnem == "pop" and ins.ops == ["rbp"]:
                continue
            # --- local var access ---
            for opnd in ins.ops:
                if "[rbp" in opnd:
                    slot = opnd.strip("[]").replace("rbp", "").replace("-", "-0x").replace("+", "+0x")
                    try:
                        off = int(slot.replace("rbp", "0") or 0, 16) if slot else 0
                    except ValueError:
                        off = 0
                    newvar(opnd)
            # --- lea -> string ref or stack var ---
            if ins.mnem == "lea" and len(ins.ops) == 2:
                dst, src = ins.ops
                if "rip" in src:
                    tgt = None
                    if "=>" in src:  # pre-computed target from disassembler
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
            # --- mov dst, src: propagate literal/var into arg registers ---
            if ins.mnem == "mov" and len(ins.ops) == 2:
                dst, src = ins.ops
                if dst in arg_regs:
                    if src in REG64 and src in pending_args:
                        pending_args[dst] = pending_args[src]
                    elif src in pending_args:
                        pending_args[dst] = pending_args[src]
                    else:
                        pending_args[dst] = src
                    continue  # pure argument marshalling: hide
                if src in pending_args and dst.startswith("[rbp"):
                    newvar(dst)
                    pf.lines.append((indent, f"{vars_[dst]} = {pending_args[src]};"))
                    continue
                if src in pending_args and dst in REG64:
                    pending_args[dst] = pending_args[src]
                    continue
            if ins.mnem == "mov" and len(ins.ops) == 2 and ins.ops[0] in arg_regs and ins.ops[1].startswith("0x"):
                pending_args[ins.ops[0]] = ins.ops[1]
                continue
            # --- xor reg,reg -> = 0 ---
            if ins.mnem == "xor" and len(ins.ops) == 2 and ins.ops[0] == ins.ops[1]:
                r = ins.ops[0]
                if r in arg_regs:
                    pending_args[r] = "0"
                pf.lines.append((indent, f"{r} = 0;"))
                continue
            # --- cmp ---
            if ins.mnem == "cmp" and len(ins.ops) == 2:
                last_cmp = ins.ops
                pf.lines.append((indent, f"/* if ({ins.ops[0]} {'==' if ins.ops[1]=='0x0' else '!='} {ins.ops[1]}) ... */"))
                continue
            # --- calls ---
            if ins.is_call:
                tgt = ins.target()
                fname = self._fname(tgt)
                pf.calls.append(fname)
                args = [pending_args.get(r, r) for r in arg_regs]
                # only show up to last non-register arg
                n = 0
                for i, a in enumerate(args):
                    if not (a in arg_regs or a in REG64):
                        n = i + 1
                calltxt = f"{fname}({', '.join(args[:max(n,0)])});"
                pf.lines.append((indent, calltxt))
                # detect system("/bin/sh") / win pattern
                if fname in ("system", "execve") and any("/bin/sh" in a for a in args[:1]):
                    pf.effects.append(("backdoor_shell", pf.string_refs.get(ins.addr, "/bin/sh")))
                pending_args = {}
                continue
            # --- syscall ---
            if ins.mnem == "syscall":
                pf.lines.append((indent, "syscall();"))
                continue
            # --- control flow ---
            if ins.is_jcc:
                indent = max(0, indent - 1)
                pf.lines.append((indent, "}"))
                continue
            if ins.is_jmp:
                continue
            if ins.mnem == "ret":
                pf.lines.append((indent, "return;"))
                continue
            # --- default: show simplified ---
            pf.lines.append((indent, f"// {ins.mnem} {', '.join(ins.ops)}".rstrip()))

        # emit var decls
        def slot_to_int(slot):
            s = slot.strip("[] ")
            try:
                if s.startswith("rbp"):
                    return int(s[3:] or "0", 16)
            except ValueError:
                pass
            return 8
        pf.var_decls = [f"char {vars_[s]}[{abs(slot_to_int(s)) or 8}];" for s in vars_]

    def _fname(self, tgt):
        if tgt is None:
            return "func_ptr"
        # plt stub resolution
        pm = self.elf.plt_map()
        if tgt in pm:
            return pm[tgt] + "@plt"
        for s in self.elf.functions():
            if s.value == tgt:
                return s.name
        return f"sub_{tgt:x}"

    def render(self, pf):
        out = [f"// {pf.name} @ {pf.addr:#x}  (decompiled by AntPwn/guaidao2)"]
        out.append(f"void {pf.name}(void) {{")
        for d in getattr(pf, "var_decls", []):
            out.append(f"    {d}")
        for ind, txt in pf.lines:
            out.append("    " * (ind + 1) + txt)
        out.append("}")
        return "\n".join(out)
