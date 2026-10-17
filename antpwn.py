#!/usr/bin/env python3
"""AntPwn 命令行入口 (command-line entry)

用法 / usage:
    python3 antpwn.py analyze <binary> [--pseudo] [--func NAME] [--json out]
    python3 antpwn.py pwn     <binary> [--report out.html]

logo 与 banner 由 antpwn.cli 统一输出 / banner is printed by antpwn.cli
作者 / authors: guaidao2 · coolmoon
"""
from antpwn.cli import main

if __name__ == "__main__":
    main()
