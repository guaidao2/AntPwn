"""AntPwn CLI: bilingual (zh/en), beginner-friendly entry point
命令行入口: 分析 / 解题 / 伪代码 / 报告, 新手模式带"人话解释"
"""
import argparse
import json
import os
import sys

from . import i18n
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


def cmd_analyze(args):
    i18n.set_lang(args.lang)
    print(BANNER)
    print(i18n.t("banner_sub"))
    from .elf import ELF
    from .scanner import Scanner
    from .decompiler import Decompiler
    elf = ELF(args.binary)
    print(f"\n=== {i18n.t('recon')} ===")
    print(f"  PIE:      {i18n.t('yes') if elf.is_pie else i18n.t('no')}")
    print(f"  NX:       {i18n.t('yes') if elf.has_nx else i18n.t('no')}")
    print(f"  Canary:   {i18n.t('yes') if elf.canary else i18n.t('no')}")
    print(f"  RELRO:    {i18n.t(elf.relro) if elf.relro in ('partial','full','none') else elf.relro}")
    print(f"  ExecStack:{i18n.t('yes') if elf.has_execstack else i18n.t('no')}")
    sc = Scanner(elf)
    findings = sc.scan()
    print(f"\n=== {i18n.t('scan')} ===")
    for f in findings[:20]:
        print(f"  [{f.kind:>10}] {f.func} @ {f.addr:#x} — {f.text}  (score={f.score})")
    if args.pseudo:
        print(f"\n=== {i18n.t('decompile')} ===")
        dec = Decompiler(elf)
        for name, pf in sc.funcs.items():
            if args.funcname and name != args.funcname:
                continue
            print(dec.render(pf))
            print()
    if args.json:
        with open(args.json, "w") as fp:
            json.dump({"findings": [vars(f) | {"addr": f.addr} for f in findings]}, fp,
                      ensure_ascii=False, indent=1, default=str)
        print(f"\n[i] json -> {args.json}")


def cmd_pwn(args):
    i18n.set_lang(args.lang)
    print(BANNER)
    print(i18n.t("banner_sub"))
    print(f"target: {args.binary}\n")
    fsm = FSM(args.binary, lang=args.lang)
    ok = fsm.run()
    if args.report:
        path = save_report(fsm, args.report)
        print(f"\n[i] {i18n.t('report_saved')}: {path}")
    if ok:
        print(f"\n[+] {i18n.t('done')}  ({i18n.t('author')})")
    else:
        print(f"\n[-] {i18n.t('no_vuln') if not fsm.report_data.get('findings') else i18n.t('failed')}")
        sys.exit(1)


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--lang", default=None, choices=["zh", "en"],
                        help="language / 语言 (default: zh)")
    ap = argparse.ArgumentParser(prog="antpwn", parents=[common],
                                 description="AntPwn — CTF Pwn intelligent solver (by guaidao2)")
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
    p.set_defaults(handler=cmd_pwn)

    args = ap.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
