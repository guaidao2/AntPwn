"""AntPwn CLI: bilingual (zh/en), beginner-friendly entry point
命令行入口: 分析 / 解题 / 伪代码 / 报告, 新手模式带"人话解释"
"""
import argparse
import json
import os
import sys

from . import color, i18n
from .fsm import FSM, State
from .report import save_report

BANNER = r"""
               _                           
              | |                          
  __ _  _ __  | |_  _ __  __      __ _ __  
 / _` || '_ \ | __|| '_ \ \ \ /\ / /| '_ \ 
| (_| || | | || |_ | |_) | \ V  V / | | | |
 \__,_||_| |_| \__|| .__/   \_/\_/  |_| |_|
                   | |                     
                   |_|     CTF Pwn Solver — by guaidao2 · coolmoon
"""


def _mitigation(on):
    """Render a mitigation value: on = harder target, off = easier."""
    return color.value_yes(i18n.t("yes")) if on else color.value_no(i18n.t("no"))


def _print_pseudo(text):
    """Pseudo-code with dimmed comments and a highlighted function header."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("// "):
            print(color.dim(line))
        elif "(" in line and "{" in line:
            print(color.style(line, "bold", "bright_cyan"))
        else:
            print(line)


def cmd_analyze(args):
    i18n.set_lang(args.lang)
    print(color.style(BANNER.strip("\n"), "bright_cyan"))
    print(color.dim(i18n.t("banner_sub")))
    from .elf import ELF
    from .scanner import Scanner
    from .decompiler import Decompiler
    elf = ELF(args.binary)
    print(color.section(f"\n=== {i18n.t('recon')} ==="))
    print(f"  PIE:      {_mitigation(elf.is_pie)}")
    print(f"  NX:       {_mitigation(elf.has_nx)}")
    print(f"  Canary:   {_mitigation(elf.canary)}")
    relro = i18n.t(elf.relro) if elf.relro in ("partial", "full", "none") else elf.relro
    relro_styled = color.value_yes(relro) if elf.relro == "full" else (
        color.warn(relro) if elf.relro == "partial" else color.value_no(relro))
    print(f"  RELRO:    {relro_styled}")
    print(f"  ExecStack:{_mitigation(elf.has_execstack)}")
    sc = Scanner(elf)
    findings = sc.scan()
    print(color.section(f"\n=== {i18n.t('scan')} ==="))
    for f in findings[:20]:
        print(f"  [{color.kind(f.kind, f'{f.kind:>10}')}] {f.func} "
              f"@ {color.dim(f'{f.addr:#x}')} — {f.text}  "
              f"(score={color.score(f.score)})")
    if args.pseudo:
        print(color.section(f"\n=== {i18n.t('decompile')} ==="))
        dec = Decompiler(elf)
        for name, pf in sc.funcs.items():
            if args.funcname and name != args.funcname:
                continue
            _print_pseudo(dec.render(pf))
            print()
    if args.json:
        with open(args.json, "w") as fp:
            json.dump({"findings": [vars(f) | {"addr": f.addr} for f in findings]}, fp,
                      ensure_ascii=False, indent=1, default=str)
        print(f"\n[i] json -> {args.json}")


def cmd_pwn(args):
    i18n.set_lang(args.lang)
    print(color.style(BANNER.strip("\n"), "bright_cyan"))
    print(color.dim(i18n.t("banner_sub")))
    remote = None
    if args.remote:
        host, _, port = args.remote.rpartition(":")
        if not host or not port.isdigit():
            print(color.err("--remote expects HOST:PORT, e.g. 10.0.0.1:1337"))
            sys.exit(2)
        remote = (host, int(port))
    target = color.info(f"{args.binary}") + (
        color.warn(f"  ->  {remote[0]}:{remote[1]}") if remote else "")
    print(f"target: {target}\n")
    fsm = FSM(args.binary, lang=args.lang, remote=remote, keep_shell=args.shell)
    ok = fsm.run()
    if args.report:
        path = save_report(fsm, args.report)
        print(f"\n[i] {i18n.t('report_saved')}: {color.info(path)}")
    if ok:
        print(color.good(f"\n[+] {i18n.t('done')}  ({i18n.t('author')})"))
        if args.shell:
            fsm.interactive()
    else:
        print(color.err(f"\n[-] {i18n.t('no_vuln') if not fsm.report_data.get('findings') else i18n.t('failed')}"))
        sys.exit(1)


def cmd_view(args):
    i18n.set_lang(args.lang)
    from .elf import ELF
    from .repl import Repl
    Repl(ELF(args.binary)).run()


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--lang", default=None, choices=["zh", "en"],
                        help="language / 语言 (default: zh)")
    common.add_argument("--color", default="auto", choices=["auto", "always", "never"],
                        help="colored output / 彩色输出 (default: auto, TTY only)")
    ap = argparse.ArgumentParser(prog="antpwn", parents=[common],
                                 description="AntPwn — CTF Pwn analysis assistant (by guaidao2)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", parents=[common],
                       help="static analysis + vuln scan / 静态分析与漏洞扫描")
    a.add_argument("binary")
    a.add_argument("--pseudo", action="store_true", help="show pseudo-code / 显示伪代码")
    a.add_argument("--func", dest="funcname", help="only this function / 只看该函数")
    a.add_argument("--json", help="dump findings to json")
    a.set_defaults(handler=cmd_analyze)

    p = sub.add_parser("pwn", parents=[common], help="auto exploit / 自动解题")
    p.add_argument("binary")
    p.add_argument("--report", help="save html report / 保存 HTML 报告")
    p.add_argument("--remote", metavar="HOST:PORT",
                   help="attack a remote service / 远程目标, e.g. 10.0.0.1:1337")
    p.add_argument("-i", "--shell", action="store_true",
                   help="drop into the shell after success / 成功后进入交互 shell")
    p.set_defaults(handler=cmd_pwn)

    v = sub.add_parser("view", parents=[common], aliases=["repl"],
                       help="interactive disassembly / pseudo-code browser (r2-like)")
    v.add_argument("binary")
    v.set_defaults(handler=cmd_view)

    args = ap.parse_args()
    if args.color == "always":
        os.environ["ANTPWN_COLOR"] = "1"
    elif args.color == "never":
        os.environ["ANTPWN_COLOR"] = "0"
    args.handler(args)


if __name__ == "__main__":
    main()
