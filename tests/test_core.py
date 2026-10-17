"""AntPwn unit tests (stdlib unittest, no third-party deps).

Run: python3 -m unittest discover -s tests -v
"""
import contextlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


def _demo(name="challenges/bin/baby_bof"):
    root = pathlib.Path(__file__).resolve().parent.parent
    return str(root / name)


class TestELF(unittest.TestCase):
    def setUp(self):
        from antpwn import ELF
        self.elf = ELF(_demo())

    def test_mitigations(self):
        self.assertFalse(self.elf.is_pie)
        self.assertTrue(self.elf.has_nx)
        self.assertFalse(self.elf.canary)
        self.assertIn(self.elf.relro, ("partial", "full", "none"))

    def test_strings_and_symbols(self):
        strings = [s for _, s in self.elf.strings()]
        self.assertIn("/bin/sh", strings)
        self.assertTrue(self.elf.sym("vuln"))
        self.assertTrue(self.elf.got_map().get("gets"))

    def test_code_symbols(self):
        names = {s.name for s in self.elf.code_symbols()}
        self.assertIn("vuln", names)
        self.assertIn("win", names)

    def test_stripped_discovery(self):
        if not shutil.which("strip"):
            self.skipTest("strip not available")
        tmp = tempfile.mkdtemp(prefix="antpwn-test-")
        try:
            dst = os.path.join(tmp, "stripped")
            shutil.copy(_demo(), dst)
            subprocess.run(["strip", "-s", dst], check=True)
            from antpwn import ELF
            elf = ELF(dst)
            funcs = elf.code_symbols()
            self.assertGreater(len(funcs), 3)
            self.assertTrue(any(s.name.startswith("sub_") for s in funcs))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestAnalysis(unittest.TestCase):
    def test_disasm(self):
        from antpwn import ELF
        from antpwn.disasm import Disasm
        elf = ELF(_demo())
        sym = elf.sym("vuln")
        code = elf.read(sym.value, sym.size)
        insns = Disasm(code, sym.value).linear(len(code))
        self.assertTrue(insns)
        self.assertEqual(insns[0].addr, sym.value)
        self.assertTrue(all(b.addr > a.addr for a, b in zip(insns, insns[1:])))

    def test_decompiler(self):
        from antpwn import ELF, Decompiler
        elf = ELF(_demo())
        pf = Decompiler(elf).function(elf.sym("vuln"))
        text = Decompiler(elf).render(pf)
        self.assertIn("gets", text)
        self.assertIn("char v0[64]", text)

    def test_scanner(self):
        from antpwn import ELF, Scanner
        scanner = Scanner(ELF(_demo()))
        findings = scanner.scan()
        self.assertTrue(findings)
        kinds = {f.kind for f in findings}
        self.assertIn("bof", kinds)
        self.assertEqual(findings, sorted(findings, key=lambda f: -f.score))

    def test_gadgets(self):
        from antpwn import ELF, GadgetFinder
        g = GadgetFinder(ELF(_demo())).find_all()
        self.assertIn("ret", g)
        self.assertTrue(all(isinstance(v, list) for v in g.values()))


class TestColor(unittest.TestCase):
    def test_style_and_strip(self):
        os.environ["ANTPWN_COLOR"] = "1"
        try:
            from antpwn import color
            color._enabled = None
            styled = color.style("x", "bold", "red")
            self.assertIn("\x1b[", styled)
            self.assertEqual(color.strip(styled), "x")
            self.assertIn("!", color.kind("bof", "!"))
        finally:
            os.environ.pop("ANTPWN_COLOR", None)
            from antpwn import color
            color._enabled = None


class TestPlugins(unittest.TestCase):
    def test_register_strategy(self):
        from antpwn import exploits
        from antpwn.exploits import Strategy

        class MyStrategy(Strategy):
            name, key = "my_strategy", "my_strategy"

        exploits.register_strategy(MyStrategy)
        self.assertIn(MyStrategy, exploits.all_strategies())

    def test_register_technique(self):
        from antpwn import fsm

        def my_edges(ctx):
            return []

        fsm.register_technique(my_edges)
        self.assertIn(my_edges, fsm._EDGE_PLUGINS)


class TestRepl(unittest.TestCase):
    def setUp(self):
        from antpwn import ELF
        from antpwn.repl import Repl
        self.repl = Repl(ELF(_demo()))

    def test_vuln_marks(self):
        self.repl.cmd_vuln("")
        self.assertTrue(self.repl.findings)
        self.assertTrue(self.repl.vuln_ranges)
        hit = self.repl._vuln_hit(self.repl.vuln_ranges[0][0])
        self.assertIsNotNone(hit)

    def test_export_json(self):
        tmp = tempfile.mkdtemp(prefix="antpwn-view-")
        try:
            path = os.path.join(tmp, "out.json")
            self.repl.cmd_export(path)
            data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
            self.assertTrue(data["findings"])
            self.assertIn("mitigations", data)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_export_html(self):
        tmp = tempfile.mkdtemp(prefix="antpwn-view-")
        try:
            path = os.path.join(tmp, "out.html")
            self.repl.cmd_export(path)
            html = pathlib.Path(path).read_text(encoding="utf-8")
            self.assertIn("<table>", html)
            self.assertIn("AntPwn view", html)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_gadget_pattern(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.repl.cmd_gadget("ret")
        self.assertIn("gadget", buf.getvalue())

    def test_xrefs(self):
        self.repl._build_xrefs()
        self.assertIsNotNone(self.repl._xrefs)


class TestPackaging(unittest.TestCase):
    def test_version_consistency(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        init = (root / "antpwn" / "__init__.py").read_text(encoding="utf-8")
        proj = (root / "pyproject.toml").read_text(encoding="utf-8")
        v1 = re.search(r'__version__\s*=\s*"([^"]+)"', init).group(1)
        v2 = re.search(r'^version = "([^"]+)"', proj, re.M).group(1)
        self.assertEqual(v1, v2)


class TestDataflow(unittest.TestCase):
    """compile small targets and check the bound-correlation findings"""

    def _build(self, src):
        gcc = shutil.which("gcc")
        if not gcc:
            self.skipTest("gcc not available")
        tmp = tempfile.mkdtemp(prefix="antpwn-df-")
        c = os.path.join(tmp, "t.c")
        pathlib.Path(c).write_text(src, encoding="utf-8")
        out = os.path.join(tmp, "t")
        subprocess.run([gcc, "-fno-stack-protector", "-no-pie", "-O0",
                        "-Wno-format-security", c, "-o", out], check=True)
        return tmp, out

    def test_read_overflow_correlation_logic(self):
        """deterministic: feed the correlation pass a rendered pseudo-code text"""
        from antpwn import ELF, Scanner
        elf = ELF(_demo())
        sc = Scanner(elf)
        text = ("void main(void) {\n"
                "    char v0[64];\n"
                "    read@plt(0x0, v0, 0x12c);\n"
                "    return;\n"
                "}\n")

        class _FakeDec:
            @staticmethod
            def render(_pf):
                return text

        class _FakePf:
            lines = []

        sc.dec = _FakeDec()
        sc._dataflow(elf.sym("main"), _FakePf())
        bof = [f for f in sc.findings if f.kind == "bof"]
        self.assertTrue(bof)
        self.assertTrue(any("300" in f.text or "300" in (f.evidence or "") for f in bof))
        self.assertTrue(any("溢出" in f.text or "overflow" in f.text for f in bof))

    def test_read_overflow_is_exact(self):
        tmp, out = self._build(
            "#include <unistd.h>\n"
            "int main(void){char b[64]; read(0,b,300); return 0;}\n")
        try:
            from antpwn import ELF, Scanner
            findings = Scanner(ELF(out)).scan()
            bof = [f for f in findings if f.kind == "bof"]
            if not bof:
                self.skipTest("compiler output not recognised on this toolchain")
            self.assertTrue(any("300" in f.evidence or "300" in f.text for f in bof))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_scanf_width_is_safe(self):
        tmp, out = self._build(
            "#include <stdio.h>\n"
            "int main(void){char b[64]; scanf(\"%63s\", b); return 0;}\n")
        try:
            from antpwn import ELF, Scanner
            findings = Scanner(ELF(out)).scan()
            self.assertFalse(any(f.kind == "bof" and "scanf" in (f.evidence or "")
                                 for f in findings))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestNewStrategies(unittest.TestCase):
    def test_one_gadget_helper_missing_tool(self):
        from antpwn.exploits import find_one_gadget_offsets
        if shutil.which("one_gadget"):
            self.skipTest("one_gadget installed")
        self.assertEqual(find_one_gadget_offsets("/bin/true"), [])

    def test_csu_detection(self):
        from antpwn import ELF
        from antpwn.exploits import csu_gadgets
        elf = ELF(_demo())
        res = csu_gadgets(elf)          # may be None on modern gcc; must not raise
        if res:
            pop_addr, call_addr = res
            self.assertTrue(pop_addr and call_addr)

    def test_canary_brute_algorithm(self):
        from antpwn import ELF, Scanner, GadgetFinder
        from antpwn.exploits import ExploitContext, CanaryBrute
        from antpwn.fsm import Logger

        class FakeCtx(ExploitContext):
            pass

        elf = ELF(_demo())
        ctx = FakeCtx(elf, Scanner(elf), GadgetFinder(elf), Logger(verbose=False))
        ctx.remote = ("127.0.0.1", 1)
        brute = CanaryBrute(ctx)
        secret = b"\x00\x11\x22\x33\x44\x55\x66\x77"

        def fake_probe(payload):
            # correct guess = the buffer prefix matches canary up to the last byte
            n = len(payload) - 56
            if payload[56:] == secret[:n]:
                return b"prompt"
            return b""

        brute._probe = fake_probe
        canary = brute._brute_one_pad(56, [9999])
        self.assertEqual(canary, secret)


class TestCyclic(unittest.TestCase):
    def test_pwnlib_compatible_pattern(self):
        from antpwn.exploits import cyclic
        self.assertEqual(cyclic(8), b"aaaabaaa")
        self.assertEqual(cyclic(32), b"aaaabaaacaaadaaaeaaafaaagaaahaaa")

    def test_find_bytes_and_int(self):
        from antpwn.exploits import cyclic, cyclic_find
        pat = cyclic(128)
        self.assertEqual(cyclic_find(pat[72:80]), 72)
        self.assertEqual(cyclic_find(0x61616161), 0)      # b"aaaa"
        self.assertIsNone(cyclic_find(b"\xde\xad\xbe\xef\xde\xad\xbe\xef"))

    def test_windows_are_unique(self):
        from antpwn.exploits import cyclic_find
        from antpwn.exploits import cyclic
        pat = cyclic(256)
        seen = {}
        for i in range(0, 256 - 8, 4):
            off = cyclic_find(pat[i:i + 8])
            self.assertEqual(off, i)
            seen[off] = True


class TestColorEnv(unittest.TestCase):
    def _reset(self):
        from antpwn import color
        color._enabled = None

    def test_no_color_wins_unless_forced(self):
        import os
        old = {k: os.environ.get(k) for k in ("NO_COLOR", "ANTPWN_COLOR", "CLICOLOR")}
        try:
            os.environ["NO_COLOR"] = "1"
            os.environ["ANTPWN_COLOR"] = "1"
            self._reset()
            from antpwn import color
            self.assertFalse(color.enabled())
            os.environ["ANTPWN_COLOR"] = "always"
            self._reset()
            self.assertTrue(color.enabled())
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            self._reset()


class TestGdbLoader(unittest.TestCase):
    def test_snippet(self):
        from antpwn import gdb_loader
        line = gdb_loader.gdbinit_line()
        self.assertIn("sys.path.insert", line)
        self.assertIn("antpwn.gdbplugin.register()", line)


class TestDecompilerIR(unittest.TestCase):
    def _decompile(self, rel, fn):
        from antpwn import ELF
        from antpwn.decompiler import Decompiler
        elf = ELF(_demo(rel))
        dec = Decompiler(elf)
        pf = dec.function(elf.sym(fn))
        self.assertIsNotNone(pf)
        return dec, pf

    def test_calls_and_stack_buffers(self):
        dec, pf = self._decompile("challenges/bin/baby_bof", "vuln")
        text = dec.render(pf)
        self.assertIn("char v0[64];", text)
        self.assertIn('gets@plt(v0)', text)
        self.assertIn('puts@plt("', text)
        self.assertIn("return", text)

    def test_structuring_loop_and_branches(self):
        dec, pf = self._decompile("challenges/bin/heap_uaf", "main")
        text = dec.render(pf)
        self.assertIn("while (", text)
        self.assertIn("if (", text)
        self.assertTrue("continue;" in text or "break;" in text)
        self.assertIn("fgets@plt(", text)

    def test_o2_rsp_frame_buffer(self):
        dec, pf = self._decompile("challenges/adv/t1_o2", "entry_point")
        text = dec.render(pf)
        self.assertIn("char v0[88];", text)
        self.assertIn("read@plt(0, v0, 0x12c);", text)

    def test_loop_header_stays_inside_loop(self):
        dec, pf = self._decompile("challenges/bin/heap_uaf", "main")
        text = dec.render(pf)
        loop_at = text.find("while (1)")
        menu_at = text.find("menu();")
        self.assertGreaterEqual(loop_at, 0)
        self.assertGreater(menu_at, loop_at)
        self.assertIn("== 0) break;", text)

    def test_engine_marker_and_decls(self):
        import re as _re
        dec, pf = self._decompile("challenges/bin/baby_bof", "vuln")
        self.assertEqual(pf.engine, "ir")
        text = dec.render(pf)
        for name in set(_re.findall(r"\b(v\d+)\b", text)):
            self.assertRegex(text, r"(?:char|uint64_t) " + name + r"[\[;]")

    def test_canary_guard_hidden(self):
        dec, pf = self._decompile("challenges/adv/t2_canary", "handler")
        text = dec.render(pf)
        # the guard slot and the always-true comparison are folded away
        self.assertNotIn("flags", text)
        self.assertNotIn("__stack_chk_fail", text)
        self.assertIn("read@plt(0, v1, 0x12c);", text)

    def test_ir_cfg_and_loops(self):
        from antpwn import ELF
        from antpwn.disasm import Disasm
        from antpwn.decompiler import Decompiler
        from antpwn.ir import FunctionIR, Lifter
        elf = ELF(_demo("challenges/bin/heap_uaf"))
        sym = elf.sym("main")
        code = elf.read(sym.value, sym.size or 0x400)
        insns = Disasm(code, sym.value).recursive(len(code), [0])
        ir = FunctionIR("main", insns[0].addr)
        Lifter(elf, ir, sym.value).lift(insns, Decompiler(elf).strmap)
        self.assertGreater(len(ir.blocks), 3)
        self.assertTrue(ir.loops)
        self.assertTrue(any(s[0] == "call" for a in ir.order
                            for s in ir.blocks[a].stmts))


class TestDecompilerColor(unittest.TestCase):
    def test_ansi_only_when_enabled(self):
        import os
        from antpwn import ELF, color
        from antpwn.decompiler import Decompiler
        old = {k: os.environ.get(k) for k in ("ANTPWN_COLOR", "NO_COLOR")}
        try:
            os.environ["ANTPWN_COLOR"] = "1"
            os.environ.pop("NO_COLOR", None)
            color._enabled = None
            elf = ELF(_demo("challenges/bin/baby_bof"))
            dec = Decompiler(elf)
            pf = dec.function(elf.sym("vuln"))
            self.assertIn("\x1b[", dec.render_ansi(pf))
            self.assertNotIn("\x1b[", dec.render(pf))
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            color._enabled = None


class TestI386(unittest.TestCase):
    """32-bit ELF support: fixtures are assembled with as --32 + ld -m elf_i386"""

    @classmethod
    def setUpClass(cls):
        if not (shutil.which("as") and shutil.which("ld")):
            raise unittest.SkipTest("binutils (as/ld) not available")
        fixtures = pathlib.Path(__file__).resolve().parent / "fixtures"
        cls.tmp = tempfile.mkdtemp(prefix="antpwn-i386-")
        cls.bins = {}
        # capability probe: `as` may exist without 32-bit support on a runner
        probe_o = os.path.join(cls.tmp, "probe.o")
        try:
            subprocess.run(["as", "--32", str(fixtures / "i386_bof.s"),
                            "-o", probe_o], check=True, capture_output=True)
            subprocess.run(["ld", "-m", "elf_i386", probe_o,
                            "-o", os.path.join(cls.tmp, "probe")],
                           check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise unittest.SkipTest(f"binutils lacks 32-bit support: {exc}")
        for name in ("i386_bof", "i386_loop", "i386_syscall", "i386_shellcode"):
            out = os.path.join(cls.tmp, name)
            src = str(fixtures / (name + ".s"))
            obj = os.path.join(cls.tmp, name + ".o")
            subprocess.run(["as", "--32", src, "-o", obj], check=True)
            extra = ["-z", "execstack"] if name == "i386_shellcode" else []
            subprocess.run(["ld", "-m", "elf_i386", *extra, obj, "-o", out],
                           check=True)
            cls.bins[name] = out
        # optional: dynamic 32-bit fixtures (needs gcc -m32 + 32-bit libc)
        src = str(fixtures / "i386_ret2libc.c")
        out = os.path.join(cls.tmp, "i386_ret2libc")
        try:
            subprocess.run(["gcc", "-m32", "-fno-stack-protector", "-no-pie",
                            "-o", out, src], check=True,
                           capture_output=True)
            cls.bins["i386_ret2libc"] = out
        except (OSError, subprocess.CalledProcessError):
            pass
        pie = os.path.join(cls.tmp, "i386_pie")
        try:
            subprocess.run(["gcc", "-m32", "-fno-stack-protector", "-pie",
                            "-fPIE", "-o", pie, src], check=True,
                           capture_output=True)
            cls.bins["i386_pie"] = pie
        except (OSError, subprocess.CalledProcessError):
            pass

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_elf32_parse_and_disasm(self):
        from antpwn import ELF
        from antpwn.disasm import Disasm
        elf = ELF(self.bins["i386_bof"])
        self.assertEqual(elf.bits, 32)
        self.assertEqual(elf.e_machine, 3)
        self.assertFalse(elf.is_pie)
        sym = elf.sym("vuln")
        self.assertTrue(sym)
        code = elf.read(sym.value, sym.size)
        insns = Disasm(code, sym.value, 32).recursive(len(code), [0])
        text = "; ".join(f"{i.mnem} {', '.join(i.ops)}" for i in insns[:4])
        self.assertIn("mov ebp, esp", text)
        self.assertIn("push 0x12c", text)

    def test_gadgets32(self):
        from antpwn import ELF, GadgetFinder
        elf = ELF(self.bins["i386_syscall"])
        names = set(GadgetFinder(elf).find_all())
        for need in ("pop eax", "pop ebx", "pop ecx", "pop edx", "int 0x80"):
            self.assertIn(need, names)

    def test_shellcode32_bytes(self):
        from antpwn.exploits import SHELLCODE32
        self.assertLessEqual(len(SHELLCODE32), 32)
        self.assertIn(b"\xcd\x80", SHELLCODE32)

    def test_process32_regs(self):
        from antpwn.debugger import Process
        proc = Process(self.bins["i386_bof"])
        try:
            try:
                proc.start()
                regs = proc.getregs()
            except Exception as exc:      # ptrace disabled / no IA32 compat
                self.skipTest(f"cannot ptrace a 32-bit process here: {exc}")
            self.assertEqual(proc.bits, 32)
            self.assertEqual(regs.eip, regs.rip)
            self.assertEqual(regs.esp, regs.rsp)
            self.assertTrue(0x08048000 <= regs.eip < 0x10000000)
        finally:
            if proc.pid:
                proc.kill()

    def test_ret2libc32_fixture(self):
        if "i386_ret2libc" not in self.bins:
            self.skipTest("gcc -m32 with 32-bit libc not available")
        from antpwn import ELF, GadgetFinder
        elf = ELF(self.bins["i386_ret2libc"])
        self.assertEqual(elf.bits, 32)
        self.assertIn("puts", elf.got_map())
        self.assertIn("read", elf.got_map())
        self.assertTrue(elf.plt_map())
        self.assertIn("ret", GadgetFinder(elf).find_all())

    def test_0f_fallback_keeps_length(self):
        from antpwn.disasm import Disasm
        # bswap eax (0f c8, no ModRM) followed by nops must not desync
        ins = Disasm(b"\x0f\xc8\x90\x90\x90", 0x1000, 64).linear(5)
        self.assertEqual([i.mnem for i in ins], ["bswap", "nop", "nop", "nop"])
        self.assertEqual(ins[0].size, 2)
        self.assertEqual(Disasm(b"\x0f\x77\x90", 0x1000, 32).decode_one(0).mnem, "emms")
        shld = Disasm(b"\x0f\xa4\xc0\x01", 0x1000, 64).decode_one(0)
        self.assertEqual(shld.size, 4)
        three = Disasm(b"\x0f\x38\x00\xc0", 0x1000, 64).decode_one(0)
        self.assertEqual(three.size, 4)

    def test_stack_arg_requires_i386_frame(self):
        from antpwn.ir import parse_mem, StackModel
        st64 = StackModel()
        st64.bits = 64
        e64 = parse_mem("[rbp+0x10]", st64, 0)
        self.assertEqual(e64[0], "var")
        self.assertEqual(st64.params, [])
        st32 = StackModel()
        st32.bits = 32
        st32.fp_frame = False
        e32 = parse_mem("[ebp+8]", st32, 0)
        self.assertEqual(e32[0], "var")
        st32.fp_frame = True
        e_arg = parse_mem("[ebp+8]", st32, 0)
        self.assertEqual(e_arg[0], "var")
        self.assertEqual(st32.params, ["arg0"])

    def test_dag_edges_honour_arch(self):
        from antpwn import ELF, Scanner, GadgetFinder
        from antpwn.exploits import ExploitContext
        from antpwn.fsm import FSM
        elf = ELF(self.bins["i386_bof"])
        fsm = FSM(self.bins["i386_bof"], use_pheromone=False)
        fsm.elf = elf
        fsm.scanner = Scanner(elf)
        ctx = ExploitContext(elf, fsm.scanner, GadgetFinder(elf), None)
        edges = {e.name: e for e in fsm.build_edges(ctx)}
        for name in ("fmt-k", "fmt-backdoor", "fmt-leak", "heap-leak"):
            self.assertIn(name, edges)
            self.assertFalse(edges[name].feasible(ctx),
                             f"{name} must be blocked on i386")

    def test_i386_push_save_is_not_an_argument(self):
        from antpwn import ELF
        from antpwn.decompiler import Decompiler
        elf = ELF(self.bins["i386_bof"])
        dec = Decompiler(elf)
        text = dec.render(dec.function(elf.sym("demo")))
        self.assertIn("sink(0x41)", text)
        self.assertNotIn("sink(0x41, ebx)", text)

    def test_i386_inc_dec_decode(self):
        from antpwn.disasm import Disasm
        d = Disasm(b"\x40\x48\x43", 0x1000, 32)
        self.assertEqual((d.decode_one(0).mnem, d.decode_one(0).ops), ("inc", ["eax"]))
        self.assertEqual(d.decode_one(1).mnem, "dec")
        self.assertEqual(d.decode_one(1).ops, ["eax"])
        self.assertEqual(d.decode_one(2).mnem, "inc")
        self.assertEqual(d.decode_one(2).ops, ["ebx"])

    def test_movsxd_regression(self):
        from antpwn.disasm import Disasm
        ins = Disasm(b"\x48\x63\xc0", 0x1000, 64).decode_one(0)
        self.assertEqual(ins.mnem, "movsxd")
        self.assertEqual(ins.size, 3)

    def test_unknown_prefixed_sse_length(self):
        from antpwn.disasm import Disasm
        ins = Disasm(b"\x66\x0f\x6f\xc0", 0x1000, 32).decode_one(0)
        self.assertEqual(ins.size, 4)   # length must include the 0x66 prefix
        ins2 = Disasm(b"\x48\x0f\x28\xc0", 0x1000, 64).decode_one(0)
        self.assertEqual(ins2.size, 4)

    def test_i386_cdecl_params_and_syscall_ret(self):
        from antpwn import ELF
        from antpwn.decompiler import Decompiler
        elf = ELF(self.bins["i386_bof"])
        dec = Decompiler(elf)
        text = dec.render(dec.function(elf.sym("read")))
        self.assertIn("uint32_t arg0", text)
        self.assertIn("uint32_t arg2", text)
        self.assertIn("syscall()", text)
        self.assertNotIn("return 0x3", text)

    def test_i386_no_duplicate_function_entries(self):
        from antpwn import ELF, Scanner
        elf = ELF(self.bins["i386_bof"])
        bof = [f for f in Scanner(elf).scan() if f.kind == "bof"]
        self.assertEqual(len(bof), 1, [f.func for f in bof])

    def test_arch_guards(self):
        from antpwn import ELF, Scanner, GadgetFinder
        from antpwn.exploits import ExploitContext, FmtGOT, HeapUAF, Ret2Text
        elf = ELF(self.bins["i386_bof"])
        ctx = ExploitContext(elf, Scanner(elf), GadgetFinder(elf), None)
        self.assertFalse(FmtGOT(ctx).supported())
        self.assertFalse(HeapUAF(ctx).supported())
        self.assertTrue(Ret2Text(ctx).supported())
        from antpwn.exploits import Ret2OneGadget
        self.assertFalse(Ret2OneGadget(ctx).supported())

    def test_i386_pie_plt_map(self):
        if "i386_pie" not in self.bins:
            self.skipTest("gcc -m32 -pie not available")
        from antpwn import ELF
        elf = ELF(self.bins["i386_pie"])
        self.assertEqual(elf.bits, 32)
        self.assertTrue(elf.is_pie)
        names = set(elf.plt_map().values())
        self.assertTrue(names, "32-bit PIE PLT stubs (ff a3) not resolved")
        self.assertIn("puts", names)
        self.assertIn("read", names)

    def test_decompiler_i386(self):
        from antpwn import ELF
        from antpwn.decompiler import Decompiler
        elf = ELF(self.bins["i386_bof"])
        dec = Decompiler(elf)
        text = dec.render(dec.function(elf.sym("vuln")))
        self.assertIn("read(0, v0, 0x12c)", text)
        self.assertIn("char v0[64];", text)
        loop = ELF(self.bins["i386_loop"])
        text2 = Decompiler(loop).render(Decompiler(loop).function(loop.sym("compute")))
        self.assertIn("while (v0 < 0xa)", text2)
        self.assertIn("v1 = v1 + v0", text2)
        self.assertIn("uint32_t", text2)


class TestPackagingFiles(unittest.TestCase):
    def test_pyproject_and_ci(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        proj = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('[project.scripts]', proj)
        self.assertIn('antpwn = "antpwn.cli:main"', proj)
        self.assertTrue((root / ".github/workflows/test.yml").is_file())
        self.assertTrue((root / ".github/workflows/release.yml").is_file())

    def test_gdb_plugin_assets(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        loader = (root / "antpwn-gdb.py").read_text(encoding="utf-8")
        plugin = (root / "antpwn/gdbplugin.py").read_text(encoding="utf-8")
        self.assertIn("gdbplugin.register()", loader)
        self.assertIn("gdb.Command", plugin)
        for cmd in ("recon", "vuln", "disas", "pseudo", "xrefs", "offset",
                    "trace", "plan", "lang", "prompt"):
            self.assertIn(f'"{cmd}"', plugin)
        self.assertIn("gdb.prompt_hook", plugin)
        self.assertIn("set pagination off", plugin)


if __name__ == "__main__":
    unittest.main()
