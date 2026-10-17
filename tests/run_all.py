#!/usr/bin/env python3
"""AntPwn full regression: solve every challenge (built-in + blind tests)
批量回归: 自动解题所有靶场题与盲测题 — by guaidao2"""
import subprocess
import sys
import time

TARGETS = [
    "challenges/bin/baby_bof",
    "challenges/bin/ret2libc",
    "challenges/bin/r2syscall",
    "challenges/bin/fmt_got",
    "challenges/bin/shellcode64",
    "challenges/bin/srop",
    "challenges/bin/pivot",
    "challenges/bin/heap_uaf",
    "challenges/blind/mystery1",
    "challenges/blind/mystery2",
    "challenges/adv/t1_o2",
]

# unsolvable-by-design: correct behaviour = graceful failure + diagnosis
EXPECTED_FAIL = [
    "challenges/adv/t2_canary",   # canary on, no leak channel
    "challenges/adv/t3_pie",      # PIE on, no leak channel
]

def main():
    ok = fail = okxf = badxf = 0
    for t in TARGETS:
        t0 = time.time()
        try:
            r = subprocess.run(
                [sys.executable, "-m", "antpwn.cli", "pwn", t],
                capture_output=True, text=True, timeout=120, cwd=".")
            out = r.stdout + r.stderr
            won = "已被拿下" in out or "pwned" in out
            strat = next((l.strip() for l in out.splitlines() if "strategy ==" in l), "")
        except subprocess.TimeoutExpired:
            won, strat = False, "timeout"
        dt = time.time() - t0
        print(f"[{'PASS' if won else 'FAIL'}] {t:<34} {dt:5.1f}s  {strat}")
        ok += won
        fail += not won
    for t in EXPECTED_FAIL:
        t0 = time.time()
        try:
            r = subprocess.run(
                [sys.executable, "-m", "antpwn.cli", "pwn", t],
                capture_output=True, text=True, timeout=120, cwd=".")
            out = r.stdout + r.stderr
            diagnosed = ("?" in out and "利用失败" in out) or "feasible strategies: none" in out
            crashed = "Traceback" in out
        except subprocess.TimeoutExpired:
            diagnosed, crashed = False, True
        dt = time.time() - t0
        good = diagnosed and not crashed
        print(f"[{'XFAIL' if good else 'BAD!'}] {t:<33} {dt:5.1f}s  (expected graceful failure + diagnosis)")
        okxf += good
        badxf += not good
    print(f"\n== solved {ok}/{ok+fail} · expected-fail handled {okxf}/{okxf+badxf} ==")
    return 0 if (fail == 0 and badxf == 0) else 1

if __name__ == "__main__":
    sys.exit(main())
