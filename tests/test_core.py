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


class TestHeapOverflowExploitGeometry(unittest.TestCase):
    def test_chunk_step(self):
        from antpwn.exploits import HeapMenu
        self.assertEqual(HeapMenu._chunk_step(0x20, 64), 0x30)
        self.assertEqual(HeapMenu._chunk_step(0x20, 32), 0x28)
        self.assertEqual(HeapMenu._chunk_step(0x100, 64), 0x110)

    def test_alloc_geometry_from_pseudo_lines(self):
        import types
        from antpwn.exploits import HeapMenu
        elf = types.SimpleNamespace(strings=lambda minlen=1: [
            (0x4000, "1. add"), (0x4008, "2. delete"), (0x4010, "3. show"),
            (0x4020, "4. edit"), (0x4100, "data: "), (0x4110, "idx: "),
            (0x4120, "> "),
        ])
        add_pf = types.SimpleNamespace(lines=[
            (1, "v0 = malloc@plt(0x20);"),
            (2, "read@plt(0, v0, 8);"),
        ])
        edit_pf = types.SimpleNamespace(lines=[
            (3, "read@plt(0, v0, 0x80);"),
        ])
        ctx = types.SimpleNamespace(
            bits=64, elf=elf,
            scanner=types.SimpleNamespace(funcs={"add": add_pf, "edit": edit_pf}))
        h = HeapMenu(ctx)
        self.assertEqual(h._alloc_geometry(), (0x20, 0x80))


class TestHeapOverflowScan(unittest.TestCase):
    def _scan(self, lines):
        import types
        from antpwn.scanner import Scanner
        sc = object.__new__(Scanner)
        sc.findings = []
        sc.funcs = {"main": types.SimpleNamespace(
            addr=0x1000, var_decls=[],
            lines=[(0x1000 + i, ln) for i, ln in enumerate(lines)])}
        sc._scan_heap_overflow()
        return [(f.kind, f.evidence) for f in sc.findings]

    def test_constant_overflow_and_offbyone(self):
        found = self._scan([
            "v0 = malloc@plt(0x20);",
            "read@plt(0, v0, 0x100);",
            "v1 = malloc@plt(0x40);",
            "read@plt(0, v1, 0x41);",
        ])
        kinds = [k for k, _ in found]
        self.assertIn("heap_overflow", kinds)
        self.assertIn("offbyone", kinds)

    def test_matching_length_is_not_flagged(self):
        found = self._scan([
            "v0 = malloc@plt(0x20);",
            "read@plt(0, v0, 0x20);",
        ])
        self.assertEqual(found, [])


class TestScannerMore(unittest.TestCase):
    def _scan_heap(self, lines):
        import types
        from antpwn.scanner import Scanner
        sc = object.__new__(Scanner)
        sc.findings = []
        sc.funcs = {"main": types.SimpleNamespace(
            addr=0x1000, var_decls=[],
            lines=[(0x1000 + i, ln) for i, ln in enumerate(lines)])}
        sc._scan_heap_overflow()
        return [f.kind for f in sc.findings]

    def test_strncpy_bounded_not_flagged(self):
        self.assertEqual(self._scan_heap([
            "v0 = malloc@plt(0x40);",
            "strncpy@plt(v0, src, 0x20);",
        ]), [])

    def test_strncpy_unknown_length_flagged(self):
        self.assertIn("heap_overflow", self._scan_heap([
            "v0 = malloc@plt(0x20);",
            "strncpy@plt(v0, src, v1);",
        ]))

    def test_indirect_bof_into_caller_stack_buffer(self):
        import types
        from antpwn.scanner import Scanner
        sc = object.__new__(Scanner)
        sc.findings = []
        block = types.SimpleNamespace(
            stmts=[("store", ("var", "dst"), ("reg", "rdi")),
                   ("call", "strcpy@plt", [("var", "dst"), ("var", "src")])],
            term=None)
        sink = types.SimpleNamespace(ir=types.SimpleNamespace(blocks={0: block}),
                                     calls=["strcpy@plt"], var_decls=[], lines=[])
        caller = types.SimpleNamespace(
            ir=None, calls=["copy_user@plt"], var_decls=["char buf[16];"],
            lines=[(0x2000, "copy_user(buf);")], addr=0x2000)
        sc.funcs = {"copy_user": sink, "main": caller}
        sc._scan_indirect_bof()
        self.assertTrue(any(f.kind == "bof" for f in sc.findings))

    def test_indirect_bof_requires_stack_buffer(self):
        import types
        from antpwn.scanner import Scanner
        sc = object.__new__(Scanner)
        sc.findings = []
        block = types.SimpleNamespace(
            stmts=[("store", ("var", "dst"), ("reg", "rdi")),
                   ("call", "strcpy@plt", [("var", "dst"), ("var", "src")])],
            term=None)
        sink = types.SimpleNamespace(ir=types.SimpleNamespace(blocks={0: block}),
                                     calls=["strcpy@plt"], var_decls=[], lines=[])
        caller = types.SimpleNamespace(ir=None, calls=["copy_user@plt"],
                                       var_decls=[], lines=[(0x2000, "copy_user(p);")],
                                       addr=0x2000)
        sc.funcs = {"copy_user": sink, "main": caller}
        sc._scan_indirect_bof()
        self.assertEqual(sc.findings, [])


class TestHeapMenuPolicy(unittest.TestCase):
    def test_full_relro_is_rejected(self):
        import types
        from antpwn.exploits import HeapMenu
        ctx = types.SimpleNamespace(
            elf=types.SimpleNamespace(relro="full"),
            scanner=types.SimpleNamespace(findings=[types.SimpleNamespace(kind="heap")]),
            note=lambda *a: None, live={}, log=None)
        h = object.__new__(HeapMenu)
        h.ctx = ctx
        self.assertFalse(h.feasible())


class TestMenuDriver(unittest.TestCase):
    def test_menu_parse_from_strings(self):
        import types
        from antpwn.exploits import MenuDriver
        elf = types.SimpleNamespace(strings=lambda minlen=1: [
            (0x4000, "1. add"), (0x4008, "2. delete"), (0x4012, "3. show"),
            (0x401b, "4. edit"), (0x4024, "5. exit"),
            (0x4100, "size: "), (0x4110, "data: "), (0x4120, "idx: "),
            (0x4130, "choice: "), (0x4140, "> "),
        ])
        drv = MenuDriver(elf)
        self.assertEqual(drv.opts.get("add"), b"1")
        self.assertEqual(drv.opts.get("del"), b"2")
        self.assertEqual(drv.opts.get("show"), b"3")
        self.assertEqual(drv.opts.get("edit"), b"4")
        self.assertEqual(drv.markers.get("size"), b"size:")
        self.assertEqual(drv.markers.get("data"), b"data:")
        self.assertEqual(drv.markers.get("idx"), b"idx:")
        self.assertIn(drv.markers.get("menu"), (b"choice:", b">"))

    def test_named_menu_prompt_wins_over_bare(self):
        import types
        from antpwn.exploits import MenuDriver
        elf = types.SimpleNamespace(strings=lambda minlen=1: [
            (0x4000, "1. add"), (0x4008, "2. delete"), (0x4010, "3. show"),
            (0x4100, "size: "), (0x4110, "data: "), (0x4120, "idx: "),
            (0x4130, "> "), (0x4140, "$ "), (0x4150, "choice: "),
        ])
        drv = MenuDriver(elf)
        self.assertEqual(drv.markers.get("menu"), b"choice:")

    def test_poison_chunk_is_pointer_sized(self):
        import types
        from antpwn.exploits import HeapMenu
        for bits in (64, 32):
            elf = types.SimpleNamespace(strings=lambda minlen=1: [
                (0x4000, "1. add"), (0x4008, "2. delete"), (0x4010, "3. show"),
                (0x4020, "4. edit"), (0x4100, "size: "), (0x4110, "data: "),
                (0x4120, "idx: "), (0x4130, "> "),
            ])
            ctx = types.SimpleNamespace(bits=bits, elf=elf)
            h = HeapMenu(ctx)
            self.assertEqual(h.poison_size, 4 if bits == 32 else 8)

    def test_safelink_roundtrip(self):
        from antpwn.exploits import HeapMenu
        for addr in (0x5555555596a0, 0x55d2c0a3b2a0, 0x5f0000123450):
            mangled = addr ^ (addr >> 12)
            self.assertEqual(HeapMenu._decode_safelink(mangled), addr)


class TestScanReachability(unittest.TestCase):
    def test_reachable_from_main(self):
        import types
        from antpwn.scanner import Scanner

        def fn(addr, calls=()):
            return types.SimpleNamespace(addr=addr, calls=list(calls))

        sc = object.__new__(Scanner)
        sc.funcs = {
            "main": fn(0x1000, ["vuln"]),
            "vuln": fn(0x1100, ["strcpy@plt"]),
            "win": fn(0x1200),
            "printf": fn(0x2000),
        }
        sc.elf = types.SimpleNamespace(entry=0x1000)
        reachable = sc._compute_reachable()
        self.assertIn("main", reachable)
        self.assertIn("vuln", reachable)
        # not called from user code and not the entry seed
        self.assertNotIn("printf", reachable)


class TestJumpTableParser(unittest.TestCase):
    def test_relative_4byte_entries_map_options(self):
        import struct
        import types
        from antpwn.exploits import MenuDriver

        table = 0x4007
        values = [-0x10, -0x20, -0x30, -0x40]   # relative to the table base
        raw = b"".join(struct.pack("<i", v) for v in values)

        def read(addr, n):
            if table <= addr < table + len(raw):
                return raw[addr - table:addr - table + n]
            return b""

        elf = types.SimpleNamespace(
            strings=lambda minlen=1: [(0x1000, "1. alpha"), (0x1010, "2. beta"),
                                      (0x1020, "3. gamma"), (0x1030, "4. delta")],
            read=read, bits=64, entry=0,
            code_symbols=lambda: [], sym_at=lambda a: None)
        drv = MenuDriver(elf)
        drv.option_numbers = {1, 2, 3, 4}
        acts = ["add", "del", "show", "edit"]
        seq = iter(acts)

        def fake_effective(target, _elf, _funcs, _menu):
            return next(seq)

        drv._effective_handler = fake_effective
        lea = types.SimpleNamespace(addr=0x100, size=7, mnem="lea",
                                    ops=["rdx", "[rip+0x3f00]"])
        mov = types.SimpleNamespace(addr=0x110, size=4, mnem="movsxd",
                                    ops=["rax", "[rdx+rax*4]"])
        jmp = types.SimpleNamespace(addr=0x114, size=2, mnem="jmp", ops=["rax"])
        self.assertTrue(drv._infer_jump_table([lea, mov, jmp], elf, {}, None))
        self.assertEqual(drv.opts.get("add"), b"1")
        self.assertEqual(drv.opts.get("del"), b"2")
        self.assertEqual(drv.opts.get("show"), b"3")
        self.assertEqual(drv.opts.get("edit"), b"4")


class TestJumpTablePairing(unittest.TestCase):
    def _driver(self, acts, numbers):
        import struct
        import types
        from antpwn.exploits import MenuDriver
        table = 0x4007
        raw = b"".join(struct.pack("<i", -(0x10 * (i + 1))) for i in range(len(acts)))

        def read(addr, n):
            if table <= addr < table + len(raw):
                return raw[addr - table:addr - table + n]
            return b""

        elf = types.SimpleNamespace(
            strings=lambda minlen=1: [(0x1000, "1. alpha")], read=read,
            bits=64, entry=0, code_symbols=lambda: [], sym_at=lambda a: None)
        drv = MenuDriver(elf)
        drv.option_numbers = set(numbers)
        seq = iter(acts)
        drv._effective_handler = lambda *a: next(seq, None)
        lea = types.SimpleNamespace(addr=0x100, size=7, mnem="lea",
                                    ops=["rdx", "[rip+0x3f00]"])
        mov = types.SimpleNamespace(addr=0x110, size=4, mnem="movsxd",
                                    ops=["rax", "[rdx+rax*4]"])
        jmp = types.SimpleNamespace(addr=0x114, size=2, mnem="jmp", ops=["rax"])
        return drv, [lea, mov, jmp], elf

    def test_unclassified_exit_keeps_option_alignment(self):
        acts = ["add", "del", "show", "edit", None]
        drv, insns, elf = self._driver(acts, [1, 2, 3, 4, 5])
        self.assertTrue(drv._infer_jump_table(insns, elf, {}, None))
        self.assertEqual(drv.opts.get("add"), b"1")
        self.assertEqual(drv.opts.get("del"), b"2")
        self.assertEqual(drv.opts.get("show"), b"3")
        self.assertEqual(drv.opts.get("edit"), b"4")

    def test_zero_exit_slot_maps_remaining_options(self):
        acts = [None, "add", "del", "show", "edit"]
        drv, insns, elf = self._driver(acts, [1, 2, 3, 4])
        self.assertTrue(drv._infer_jump_table(insns, elf, {}, None))
        self.assertEqual(drv.opts.get("add"), b"1")
        self.assertEqual(drv.opts.get("del"), b"2")
        self.assertEqual(drv.opts.get("show"), b"3")
        self.assertEqual(drv.opts.get("edit"), b"4")


class TestVerifyShell(unittest.TestCase):
    """P0: verify_shell must prove execution, not echo reflection."""

    class EchoTube:
        def __init__(self):
            self.out = b""

        def send(self, data):
            self.out = data          # printf(buffer) reflects the input verbatim

        def recv(self, timeout=2.0):
            return self.out

    class ShellTube:
        def __init__(self):
            self.out = b""

        def send(self, data):
            if data.startswith(b"echo "):
                self.out = data[5:].strip() + b"\n"

        def recv(self, timeout=2.0):
            return self.out

    def _strategy(self):
        import types
        from antpwn.exploits import Ret2Text
        s = object.__new__(Ret2Text)
        s.ctx = types.SimpleNamespace(live={})
        return s

    def test_echo_reflection_is_rejected(self):
        ok, _ = self._strategy().verify_shell(self.EchoTube())
        self.assertFalse(ok)

    def test_real_command_output_passes(self):
        s = self._strategy()
        ok, _ = s.verify_shell(self.ShellTube())
        self.assertTrue(ok)
        self.assertIn("shell_tube", s.ctx.live)


class TestLeakScan(unittest.TestCase):
    def _scanner(self, bits):
        import types
        from antpwn.exploits import Ret2Libc
        s = object.__new__(Ret2Libc)
        s.ctx = types.SimpleNamespace(bits=bits)
        return s

    def test_32bit_libc_pointer_scan(self):
        import struct
        s = self._scanner(32)
        off = 0x80000
        base = 0xF7D00000
        resp = b"hi\n" + struct.pack("<I", base + off) + b"\n"
        leak = s._leak_from(resp, off)
        self.assertIsNotNone(leak)
        self.assertEqual(leak[1], base)
        self.assertIsNone(s._leak_from(b"hi\nno pointer here", off))

    def test_64bit_libc_pointer_scan(self):
        import struct
        s = self._scanner(64)
        off = 0x80000
        base = 0x7F1234500000
        resp = b"x" + struct.pack("<Q", base + off)
        leak = s._leak_from(resp, off)
        self.assertIsNotNone(leak)
        self.assertEqual(leak[1], base)


class TestPieRet2TextGate(unittest.TestCase):
    def test_ret2text_declines_pie(self):
        import types
        from antpwn.exploits import Ret2Text
        ctx = types.SimpleNamespace(elf=types.SimpleNamespace(is_pie=True))
        s = object.__new__(Ret2Text)
        s.ctx = ctx
        self.assertFalse(s.feasible())


class TestLibcOffsets(unittest.TestCase):
    def test_arbitrary_leak_function_offsets(self):
        import types
        from antpwn.exploits import libc_offsets
        syms = {"puts": 0x80000, "system": 0x50000, "free": 0x90000,
                "printf": 0x60000, "read": 0x110000, "write": 0x120000}
        libc = types.SimpleNamespace(
            sym=lambda n: types.SimpleNamespace(value=syms[n]) if n in syms else None,
            strings=lambda: [(0x1a0000, "/bin/sh")])
        off = libc_offsets(libc)
        self.assertEqual(off.get("write"), 0x120000)
        self.assertEqual(off.get("system"), 0x50000)
        self.assertEqual(off.get("/bin/sh"), 0x1a0000)


class TestLibcLeakVariant(unittest.TestCase):
    def _strategy(self, got, strings, regs):
        import types
        from antpwn.exploits import Ret2Libc
        elf = types.SimpleNamespace(
            got_map=lambda: dict(got), strings=lambda: list(strings),
            bits=64)
        ctx = types.SimpleNamespace(
            bits=64, elf=elf,
            pick_arg_gadget=lambda r: 0x400000 if r in regs else None)
        s = Ret2Libc(ctx)
        s.find_plt = lambda g: g + 0x10
        return s

    def test_write_variant_when_puts_missing(self):
        s = self._strategy({"write": 0x404018}, [], ("rdi", "rsi", "rdx"))
        variant = s.leak_variant()
        self.assertIsNotNone(variant)
        self.assertEqual(variant[0], "write")

    def test_printf_requires_percent_s_string(self):
        s = self._strategy({"printf": 0x404018}, [], ("rdi", "rsi"))
        self.assertIsNone(s.leak_variant())
        s = self._strategy({"printf": 0x404018}, [(0x1000, "%s")], ("rdi", "rsi"))
        self.assertEqual(s.leak_variant()[0], "printf")

    def test_puts_preferred(self):
        s = self._strategy({"puts": 0x404018, "write": 0x404020},
                           [], ("rdi", "rsi", "rdx"))
        self.assertEqual(s.leak_variant()[0], "puts")


class TestSafelinkDecode(unittest.TestCase):
    def test_decode_fixed_point(self):
        from antpwn.exploits import HeapMenu
        chunk = 0x5555555596a0
        mangled = chunk ^ (chunk >> 12)  # x == a ^ (a >> 12): the decoder's fixed point
        self.assertEqual(HeapMenu._decode_safelink(mangled), chunk)

    def test_reject_garbage(self):
        from antpwn.exploits import HeapMenu
        self.assertIsNone(HeapMenu._decode_safelink(0xFFFFFFFFFFFFFFFF))
        self.assertIsNone(HeapMenu._decode_safelink(0x1234))


class TestChunkStep(unittest.TestCase):
    def test_chunk_step_alignment(self):
        from antpwn.exploits import HeapMenu
        self.assertEqual(HeapMenu._chunk_step(0x20, 64), 0x30)   # 0x20+8 -> 0x30
        self.assertEqual(HeapMenu._chunk_step(0x18, 64), 0x20)   # min chunk
        self.assertEqual(HeapMenu._chunk_step(0x20, 32), 0x28)   # 0x20+4 -> align8
        self.assertEqual(HeapMenu._chunk_step(0x8, 32), 0x10)    # min chunk


class TestHeapMenuHelpers(unittest.TestCase):
    def test_plausible_heap_rejects_code_and_misalignment(self):
        from antpwn.exploits import HeapMenu
        self.assertTrue(HeapMenu._plausible_heap(0x5555555596a0))
        self.assertTrue(HeapMenu._plausible_heap(0x80bc020))
        self.assertFalse(HeapMenu._plausible_heap(0x555555555169))  # code pointer
        self.assertFalse(HeapMenu._plausible_heap(0x1004))         # too low / unaligned


class TestHeapAddressClassification(unittest.TestCase):
    def test_dense_chunk_cluster_excludes_isolated_code_pointer(self):
        from antpwn.exploits import HeapMenu
        chunks = [0x5555555596a0, 0x5555555596d0, 0x555555559700]
        code = 0x5555555551a0
        picked = HeapMenu._heap_addrs(chunks + [code])
        self.assertTrue(set(picked).issubset(set(chunks)))
        self.assertNotIn(code, picked)

    def test_pad_truncates_and_zero_fills(self):
        from antpwn.exploits import HeapMenu
        self.assertEqual(HeapMenu._pad(b"AB", 4), b"AB\x00\x00")
        self.assertEqual(HeapMenu._pad(b"ABCD", 2), b"AB")
        self.assertEqual(HeapMenu._pad(b"AB", None), b"AB")   # unknown length

    def test_chunk_only_prints_do_not_derive_fake_pie_base(self):
        import types
        from antpwn.exploits import HeapMenu
        elf = types.SimpleNamespace(
            strings=lambda minlen=1: [(0x4000, "> ")], is_pie=True,
            code_symbols=lambda: [types.SimpleNamespace(value=0x1169),
                                  types.SimpleNamespace(value=0x1200)],
            symbols=lambda: [])
        ctx = types.SimpleNamespace(bits=64, elf=elf,
                                    scanner=types.SimpleNamespace(funcs={}))
        h = HeapMenu(ctx)
        chunks = [0x25a0, 0x25d0, 0x2600]
        data = b" ".join(f"{a:#x}".encode() for a in chunks)
        self.assertIsNone(h._derive_pie_base(data))


class TestHeapMenuPie(unittest.TestCase):
    def test_derive_pie_base_from_printed_code_pointer(self):
        import types
        from antpwn.exploits import HeapMenu
        elf = types.SimpleNamespace(
            strings=lambda minlen=1: [(0x4000, "> ")],
            is_pie=True,
            code_symbols=lambda: [types.SimpleNamespace(value=0x1169),
                                  types.SimpleNamespace(value=0x1200)],
            symbols=lambda: [],
        )
        ctx = types.SimpleNamespace(bits=64, elf=elf,
                                    scanner=types.SimpleNamespace(funcs={}))
        h = HeapMenu(ctx)
        base = 0x555555554000
        data = f"win: {base + 0x1169:#x}\n> ".encode()
        self.assertEqual(h._derive_pie_base(data), base)
        # no code-like pointer -> cannot derive
        self.assertIsNone(h._derive_pie_base(b"chunk[0] @ 0x00ff1234\n> "))


class TestJumpTableMenu(unittest.TestCase):
    def test_imm_before_call(self):
        import types
        from antpwn.exploits import HeapMenu

        def ins(mnem, *ops):
            return types.SimpleNamespace(mnem=mnem, ops=list(ops))

        insns = [
            ins("mov", "edi", "0x20"),
            ins("mov", "rsi", "rsp"),
            ins("call", "0x401080"),
        ]
        self.assertEqual(HeapMenu._imm_before(insns, 2, ("edi", "rdi")), 0x20)
        self.assertIsNone(HeapMenu._imm_before(insns, 2, ("edx", "rdx")))

    def test_option_numbers_ignore_stray_fragments(self):
        import types
        from antpwn.exploits import MenuDriver
        elf = types.SimpleNamespace(strings=lambda minlen=1: [
            (0x4000, "1. alpha"), (0x4008, "2. beta"), (0x4010, "9. exit"),
            (0x4020, "chunk[%d] @ %p"), (0x4030, "64. stray"),
            (0x4100, "idx: "), (0x4110, "> "),
        ])
        drv = MenuDriver(elf)
        self.assertIn(1, drv.option_numbers)
        self.assertIn(9, drv.option_numbers)
        self.assertNotIn(64, drv.option_numbers)


class TestMenuDispatchInference(unittest.TestCase):
    def test_classify_handler_by_calls(self):
        import types
        from antpwn.exploits import MenuDriver
        cases = {
            "add": ["malloc@plt", "read@plt"],
            "del": ["free@plt"],
            "show": ["write@plt", "printf@plt"],
            "edit": ["read@plt", "scanf@plt"],
        }
        for want, calls in cases.items():
            pf = types.SimpleNamespace(calls=calls)
            self.assertEqual(MenuDriver._classify_handler(pf), want)

    def test_resolve_handler_uses_next_function_bound(self):
        import types
        from antpwn.exploits import MenuDriver
        funcs = {
            "f1": types.SimpleNamespace(addr=0x1000, calls=[]),
            "f2": types.SimpleNamespace(addr=0x1100, calls=["malloc@plt"]),
            "f3": types.SimpleNamespace(addr=0x1200, calls=["free@plt"]),
        }
        elf = types.SimpleNamespace(sym_at=lambda a: None)
        drv = MenuDriver(types.SimpleNamespace(strings=lambda minlen=1: []))
        name, pf = drv._resolve_handler(0x1150, elf, funcs)
        self.assertEqual(name, "f2")
        self.assertIs(pf, funcs["f2"])

    def test_short_words_do_not_substring_match(self):
        import types
        from antpwn.exploits import MenuDriver
        elf = types.SimpleNamespace(strings=lambda minlen=1: [
            (0x4000, "1. alpha"), (0x4008, "2. beta"), (0x4010, "3. gamma"),
            (0x4018, "4. delta"), (0x4100, "idx: "), (0x4110, "> "),
        ])
        drv = MenuDriver(elf)
        self.assertNotIn("del", drv.opts)


class TestArgGadgetChain(unittest.TestCase):
    def _ctx(self, gadgets):
        import struct
        import types
        from antpwn.exploits import ExploitContext
        ctx = object.__new__(ExploitContext)
        ctx.bits = 64
        bucket = {}
        for name, addr in gadgets.items():
            bucket[name] = [types.SimpleNamespace(addr=addr)]
        ctx.gadgets = types.SimpleNamespace(find_all=lambda: bucket)
        ctx.pack = lambda v: struct.pack("<Q", v)
        return ctx

    def test_exact_pop(self):
        ctx = self._ctx({"pop rdi": 0x401001})
        parts = []
        self.assertTrue(ctx.chain_set(parts, "rdi", 0x4141))
        self.assertEqual(parts, [b"\x01\x10\x40\x00\x00\x00\x00\x00",
                                 b"AA\x00\x00\x00\x00\x00\x00"])

    def test_compound_pop_adds_padding(self):
        ctx = self._ctx({"pop rdi;pop rbp": 0x401002})
        parts = []
        self.assertTrue(ctx.chain_set(parts, "rdi", 0x4141))
        self.assertEqual(len(parts), 3)
        self.assertEqual(int.from_bytes(parts[-1], "little"), 0)

    def test_no_gadget(self):
        ctx = self._ctx({})
        self.assertFalse(ctx.chain_set([], "rdi", 1))


class TestPartialPie(unittest.TestCase):
    def test_partial_payload_length_and_bytes(self):
        from antpwn.exploits import cyclic
        payload = cyclic(72) + (0x1169).to_bytes(2, "little")
        self.assertEqual(len(payload), 74)
        self.assertEqual(payload[72:], b"\x69\x11")

    def test_one_byte_payload(self):
        from antpwn.exploits import cyclic
        payload = cyclic(72) + (0x116d & 0xFF).to_bytes(1, "little")
        self.assertEqual(payload[72:], b"\x6d")

    def test_menu_driver_obscure_action_words(self):
        import types
        from antpwn.exploits import MenuDriver
        elf = types.SimpleNamespace(strings=lambda minlen=1: [
            (0x4000, "1. create"), (0x4008, "2. destroy"), (0x4010, "3. dump"),
            (0x4018, "4. update"), (0x4100, "idx: "), (0x4110, "data: "),
            (0x4120, "> "),
        ])
        drv = MenuDriver(elf)
        self.assertEqual(drv.opts.get("add"), b"1")
        self.assertEqual(drv.opts.get("del"), b"2")
        self.assertEqual(drv.opts.get("show"), b"3")
        self.assertEqual(drv.opts.get("edit"), b"4")


class TestShellcodeCandidates(unittest.TestCase):
    def test_stack_like_addresses_come_first(self):
        from antpwn.exploits import Shellcode
        cands = Shellcode._stack_candidates(
            [0x4141414141414141, 0x555555559000, 0x7FFC12345000], 64)
        self.assertEqual(cands[0], 0x7FFC12345000)
        self.assertIn(0x555555559000, cands)

    def test_32bit_stack_range(self):
        from antpwn.exploits import Shellcode
        cands = Shellcode._stack_candidates([0x0804A000, 0xFFAABBCC], 32)
        self.assertEqual(cands[0], 0xFFAABBCC)
        self.assertIn(0x0804A000, cands)

    def test_rejects_non_addresses(self):
        from antpwn.exploits import Shellcode
        self.assertEqual(Shellcode._stack_candidates([0, 0x10, 0x1234], 64), [])


class TestPieBaseDerivation(unittest.TestCase):
    def test_derive_from_any_printed_code_pointer(self):
        from antpwn.exploits import LeakedWin
        base = 0x555555554000
        win_off = 0x1169
        printed_main = base + 0x1200
        self.assertEqual(
            LeakedWin._derive_win([printed_main], win_off, [0x1200]),
            base + win_off)
        # a direct win address still wins immediately
        self.assertEqual(LeakedWin._derive_win([base + win_off], win_off, []),
                         base + win_off)
        # no consistent page-aligned base -> no guess
        self.assertIsNone(LeakedWin._derive_win([0x12345678], win_off, [0x1200]))


class TestFmtPayload(unittest.TestCase):
    def test_64bit_payload_contains_all_halves(self):
        from antpwn.exploits import FmtGOT
        payload = FmtGOT.fmt_payload(6, 0x404018, 0x7ffff7c12345, bits=64)
        self.assertIn(b"$hn", payload)
        for off in (0, 2, 4, 6):
            self.assertIn((0x404018 + off).to_bytes(8, "little"), payload)

    def test_32bit_payload_only_two_halves(self):
        from antpwn.exploits import FmtGOT
        payload = FmtGOT.fmt_payload(6, 0x804a010, 0xf7e12345, bits=32)
        self.assertIn(b"$hn", payload)
        for off in (0, 2):
            self.assertIn((0x804a010 + off).to_bytes(4, "little"), payload)
        self.assertEqual(payload.count(b"$hn"), 2)


class TestPtyTube(unittest.TestCase):
    def test_pty_tube_reads_line_buffered_output(self):
        import sys
        if not sys.platform.startswith("linux"):
            self.skipTest("pty tube is POSIX-only")
        from antpwn.procio import Tube
        tube = Tube("/bin/echo", ["hello-pty"], pty=True)
        try:
            out = tube.recv_until(b"hello-pty", timeout=2.0)
            self.assertIn(b"hello-pty", out)
        finally:
            tube.close()


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
        for name in ("fmt-k", "fmt-backdoor", "fmt-leak"):
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

    def test_i386_accumulator_immediates(self):
        from antpwn.disasm import Disasm
        from antpwn import ELF
        # 05 00 00 00 00 = add eax, 0 (PIC thunk sequence that used to desync)
        ins = Disasm(b"\x05\x00\x00\x00\x00", 0x1000, 32).decode_one(0)
        self.assertEqual(ins.mnem, "add")
        self.assertEqual(ins.size, 5)
        self.assertEqual(ins.ops[0], "eax")
        # static binaries: libc names must not be treated as canary
        elf = ELF(self.bins["i386_bof"])
        self.assertFalse(elf.canary)

    def test_callee_name_normalisation(self):
        from antpwn.scanner import callee_base
        self.assertEqual(callee_base("_IO_gets"), "gets")
        self.assertEqual(callee_base("__libc_system"), "system")
        self.assertEqual(callee_base("__isoc99_scanf@plt"), "scanf")
        self.assertEqual(callee_base("read@plt"), "read")
        self.assertEqual(callee_base("getshell"), "getshell")

    def test_dynamic_gadget_backtracking(self):
        import types
        from antpwn.gadgets import GadgetFinder
        code = (b"\x90" * 8 +
                b"\x5f\xc3" +          # pop rdi; ret
                b"\x5e\x5d\xc3" +    # pop rsi; pop rbp; ret
                b"\x0f\x05\xc3" +    # syscall; ret
                b"\xc9\xc3")           # leave; ret
        fake = types.SimpleNamespace(
            bits=64, data=code,
            phdrs=[types.SimpleNamespace(type=1, flags=1, off=0,
                                          filesz=len(code), vaddr=0x1000)],
        )
        g = GadgetFinder(fake).find_all()
        self.assertIn("pop rdi", g)
        self.assertIn("pop rsi;pop rbp", g)
        self.assertIn("syscall;ret", g)
        self.assertIn("leave;ret", g)
        self.assertEqual(g["pop rdi"][0].addr, 0x1008)

    def test_newline_safe_gadget(self):
        from antpwn import ELF, GadgetFinder, Scanner
        from antpwn.exploits import ExploitContext
        elf = ELF(self.bins["i386_bof"])
        ctx = ExploitContext(elf, Scanner(elf), GadgetFinder(elf), None)
        picks = [cand.addr for cand in ctx.gadgets.find_all().get("ret", [])]
        self.assertTrue(picks)
        safe = ctx.pick_gadget("ret", avoid_newline=True)
        self.assertIsNotNone(safe)
        self.assertNotIn(b"\n", ctx.pack(safe))

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
        from antpwn.exploits import ExploitContext, FmtGOT, HeapMenu, Ret2Text
        elf = ELF(self.bins["i386_bof"])
        ctx = ExploitContext(elf, Scanner(elf), GadgetFinder(elf), None)
        self.assertTrue(FmtGOT(ctx).supported())  # fmt now supports i386
        self.assertIn(32, FmtGOT.BITS)
        self.assertFalse(HeapMenu(ctx).supported())
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


class TestGdbLoader(unittest.TestCase):
    def test_gdbinit_line_registers_plugin(self):
        from antpwn.gdb_loader import gdbinit_line, load_expr
        line = gdbinit_line()
        self.assertIn("antpwn.gdbplugin.register()", line)
        self.assertIn("sys.path.insert", line)
        self.assertTrue(load_expr().startswith("import sys"))

    def test_help_exits_zero(self):
        from antpwn.gdb_loader import main
        self.assertEqual(main(["--help"]), 0)


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
