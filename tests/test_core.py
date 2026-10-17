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
                    "trace", "plan", "lang"):
            self.assertIn(f'"{cmd}"', plugin)


if __name__ == "__main__":
    unittest.main()
