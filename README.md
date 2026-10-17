# AntPwn 蚁刃 — Pwn 分析助手（分析 · 决策 · 自动验证）

[中文](README.md) | [English](README.en.md)

> by guaidao2 · coolmoon

**author: guaidao2** · version 1.7.0 · 中英双语 / bilingual

> 原生静态分析 · 伪代码还原 · 漏洞扫描 · ptrace 动态调试 · 能力 DAG 规划 · 状态机驱动

**零第三方依赖**：不依赖 pwntools / gdb / capstone / ropper / angr，全部用纯 Python
原生实现（自带 ELF32/ELF64 解析器、x86-32/64 反汇编器、ptrace 调试器、libc 偏移提取）。

---

## 定位：它是助手，不是交 payload 的机器

AntPwn 的核心是**辅助分析与决策支持**：把二进制拆开、把保护认清楚、把漏洞按危险度
排出来、给出可解释的解题路线，再**自动跑一遍验证这条路线成不成立**。它不替你产出
exploit 脚本或 payload 文本，也不承诺"丢进去就出 flag"——它把判断、依据和验证结果
交给你，让你看得懂、能接管、能复现。

自动解题（`pwn`）在这个定位里是**验证手段**：工具按自己的决策树在能力图（DAG）上找
一条路，实际起进程去试；成了说明判断成立，不成就把失败原因讲清楚。所以你看到的不是
一堆魔改字节，而是一串「它在想什么、依据是什么、为什么这么走」。

依赖极少也是刻意的：纯标准库，无网、无 pip 的比赛容器里拷过去就能跑，别人也能把
`antpwn` 当库 import 进自己的工具链。

## 功能一览 / Features

| 模块 | 说明 |
|---|---|
| 静态分析 | 原生 ELF32/ELF64 解析：PIE / NX / Canary / RELRO / ExecStack 保护识别，符号、PLT/GOT、重定位 |
| 伪代码还原 | 自研反汇编器 → 类 P-code IR → CFG/支配/自然循环 → 数据流化简 → 结构化还原（if/else、while、do-while），输出带语法高亮的类 C 伪代码：`while (1) { menu(); if (fgets@plt(v0, 0x20, stdin) == 0) break; ... }` |
| 漏洞扫描 | 规则引擎 + 模式识别：栈溢出 / 格式化字符串 / UAF / 后门函数 / 危险字符串，按危险度评分 |
| 动态调试 | ctypes-ptrace 调试器：软件断点、单步、寄存器读写、内存读写、崩溃现场分析 |
| 决策与规划 | 能力 DAG + 决策树 + 蚁群：能力分 session/process 域，失败蚂蚁留下的能力可复用，偏移用崩溃取证推断，信息素按二进制特征持久化 |
| 状态机 | RECON → DECOMPILE → SCAN → STRATEGY → OFFSET → BUILD → TEST → VERIFY，每步都有中文说明 |
| 自动验证 | 8 种用户态策略，基于行为特征而非函数名；跑通即拿到交互式 shell，用来验证判断而不是替你交差 |
| 失败诊断 | 策略不可行时说明原因：缺 gadget / 缺泄露通道 / PIE 与 Canary 卡在哪一步，并给出下一步方向 |
| flag 捕获 | 拿到 shell 后自动执行 `id` / `pwd` / `ls` / `cat flag*` 等，命中 `flag{...}` 形态就直接打印 |
| 远程直打 | `--remote HOST:PORT`：本地二进制负责分析，利用流量走 TCP，同一套 DAG/策略直接打远程服务 |
| 交互 shell | `-i`：成功后接管 shell，逐行发命令、即时看输出；支持 readline（方向键/历史/Tab） |
| 交互浏览 | `view <binary>`：r2 风格交互，`info` / `ls` / `disas` / `pseudo` / `calls` / `x` / `vuln` / `xrefs` / `gadget` / `export`；漏洞自动高亮，支持 readline |
| stripped 支持 | 无符号时用入口 + 递归下降 call 目标 + 序言特征自动发现函数，`analyze`/`view` 在 stripped 二进制上照常工作 |
| 数据流扫描 | 把 `read`/`scanf` 的长度与栈缓冲大小做关联：算出确定溢出字节数、识别 off-by-one，`scanf("%63s")` 这类有宽度的不误报 |
| 新利用策略 | `one_gadget`、`ret2csu`（配合 one_gadget）、`ret2dlresolve`、canary 逐字节爆破（远程 fork 服务） |
| 插件扩展 | `register_strategy()` / `register_technique()`：外部注册策略与能力 DAG 边，不改核心代码 |
| gdb 插件 | `source antpwn-gdb.py`（或 pip 装后跑 `antpwn-gdb` 拿 .gdbinit 片段）。命令：`where`/`recon`/`vuln`（`--bp` 自动下断）/`disas`（无参围绕 `$pc`）/`pseudo`/`x $rsp`/`leak`/`maps`/`offset [gen\|0x..]`/`trace on [函数...] [--stop --max=N --dump]`/`plan`（给可粘贴下一步）/`report`/`export`/`reset`；专属提示符、Tab 补全、中英切换，和 gef/pwda 共存不抢提示符 |
| 结构化与可复现 | `pwn --json` 输出完整结果（含 trace/信息素统计）；`--no-pheromone`、`--libc PATH`、`--retries N`；`view export` 导出 html/json |
| 报告与双语 | `--lang zh / en`；`--report out.html` 输出分析结论与决策记录 |
| 终端配色 | TTY 下自动启用 ANSI 配色；`--color always / never` 或 `NO_COLOR` / `ANTPWN_COLOR` 强制开关，管道与日志自动降级为纯文本 |
| 可嵌入 | `antpwn` 是纯标准库包，CLI 只是薄壳，分析/调试/状态机均可直接当函数库用 |

## 它适合什么场景

- 比赛里拿到陌生二进制，想快速看清保护、漏洞和一条可解释的解题路线；
- 想跟着日志理解"为什么这条链能打、那条为什么不行"，而不是只拿到一个脚本；
- 要在自己的工具/平台里嵌入 ELF 分析、伪代码、ptrace 调试或自动验证能力；
- 环境受限（无网、不能装包、容器只带 python3）但需要一套完整的分析链。

如果你要的是"批量生成 exploit 脚本"那种交付形态，那和本项目的定位不同——AntPwn 选择
把过程讲清楚，把最后一公里留给人。

## 支持的用户态利用策略 / Strategies

1. **ret2text** — 检测后门函数（行为：`system("/bin/sh")`，或可疑符号名）
2. **ret2libc** — 泄露 `puts@GOT` → 算 libc 基址 → 返回溢出函数二次触发 → `system("/bin/sh")`
3. **ret2syscall** — ROP 链设置寄存器 → `execve("/bin/sh",0,0)`
4. **格式化字符串** — `%p` 喷射动态定位参数偏移；有后门则 `%hn` 覆写 GOT，**无后门则 `%s` 泄露 libc → printf@GOT→system**（通用路线）
5. **shellcode** — ExecStack + `jmp rsp`
6. **SROP** — 伪造 sigreturn 帧
7. **栈迁移 (pivot)** — 小溢出 + `leave;ret` 劫持到 bss
8. **堆利用 (heap)** — UAF 双读精确解 safe-linking chunk 地址 → tcache poisoning 落到程序指针数组 → 伪造槽位 → 泄露 libc → `free@GOT = system`

## 快速上手 / Quick Start

```bash
# 只做分析（保护识别 + 漏洞扫描 + 伪代码），不启动目标进程
python3 antpwn.py analyze ./challenges/bin/baby_bof --pseudo

# 只看某个函数的伪代码
python3 antpwn.py analyze ./baby_bof --pseudo --func vuln

# 让工具自己走一遍并验证路线（成功即拿到交互 shell）
python3 antpwn.py pwn ./challenges/bin/ret2libc

# 自动验证 + HTML 报告 + 英文输出
python3 antpwn.py pwn ./pwn200 --report out.html --lang en

# 打远程服务：本地二进制用于分析，利用流量走 TCP
python3 antpwn.py pwn ./challenges/bin/ret2libc --remote 10.0.0.1:1337

# 成功后接管 shell（逐行发命令，适合看 flag / 手工收尾）
python3 antpwn.py pwn ./challenges/bin/baby_bof -i

# r2 风格交互浏览反汇编与伪代码
python3 antpwn.py view ./challenges/bin/baby_bof

# 远程 + 指定 libc + 失败重连重试
python3 antpwn.py pwn ./pwn --remote 10.0.0.1:1337 --libc ./libc-2.31.so --retries 3

# 机器可读结果 / 可复现运行（不读写信息素）
python3 antpwn.py pwn ./pwn --json out.json --no-pheromone

# pip 安装后可以直接用 antpwn 命令
pip install .

# gdb 里直接调用分析引擎（source 一下即可）
gdb -q ./challenges/bin/baby_bof
(gdb) source /root/AntPwn/antpwn-gdb.py
(gdb) antpwn where            # 我在哪：$pc 前后指令 / $rsp 内容 / 寄存器 / backtrace
(gdb) antpwn vuln --bp        # 漏洞列表 + 可直接下的断点
(gdb) antpwn disas            # 无参就围绕当前 $pc
(gdb) antpwn trace on gets --stop --dump   # 危险调用动态观测（命中即停）
(gdb) run < antpwn_pattern.bin             # 先用 antpwn offset gen 生成
(gdb) antpwn offset           # 反解偏移，自动写 $antpwn_offset 和信息素
(gdb) antpwn plan             # 策略 + 下一条敲什么
(gdb) antpwn report           # 导出本次会话 HTML 报告
```

参数（溢出偏移、fmt 参数位置、堆 chunk 地址）全部动态探测，不依赖特定函数名或题目提示语；
判断依据和失败原因都写在终端的步骤日志与报告里。

## 作为函数库使用 / Library API

`antpwn` 是纯标准库包，CLI 只是薄壳：分析、反汇编、调试、决策、报告都能直接调用。

```python
from antpwn import ELF, Decompiler, Scanner, GadgetFinder, Process, FSM, Tube

elf  = ELF("./vuln")                 # 解析: 保护/gadgets/GOT/符号
dc   = Decompiler(elf)               # 伪代码还原
pf   = dc.function(elf.sym("main"))  # -> PseudoFunc (lines/calls/string_refs)
scan = Scanner(elf); scan.scan()     # 漏洞扫描 (bof/fmt/heap/backdoor)
gf   = GadgetFinder(elf)
rdi  = gf.first("pop rdi")           # 首个 pop rdi 地址, 找不到返回 None
proc = Process("./vuln"); proc.start()
proc.send(b"AAAA\n"); proc.cont()   # ptrace 调试: 寄存器/内存读写/断点
regs = proc.getregs(); mem = proc.read_mem(regs.rsp, 0x40)

fsm = FSM("./vuln")                  # 决策树 × 蚁群 × 能力 DAG
ok  = fsm.run()                      # -> True 且 report_data 带全程记录
```

完整接口（模块、参数、数据结构、扩展示例、坑）见 **[docs/API.md](docs/API.md)**。

把上面的对象接到自己的脚本、平台或比赛工具里，就是 AntPwn 作为"助手"的另一种用法。

## 自测 / 验证

```bash
bash challenges/build.sh      # 重建 8 道内置靶场题
python3 tests/run_all.py      # 11/11 全部拿下（8 靶场 + 2 盲测 + 1 优化题）
                              # 另 2 道无解题（t2_canary / t3_pie）验证"优雅失败 + 诊断"
```

**盲测证明泛化性**（`challenges/blind/`，函数名/提示语/偏移与开发集完全不同）：
- `mystery1`：无后门、无 /bin/sh、陌生函数名 → 自动走 ret2libc 通用泄露链（通过）
- `mystery2`：格式化字符串且无后门 → 自动走 fmt→libc 通用路线（通过）

对 `/bin/ls`（stripped + PIE + Full RELRO）分析不崩溃，正常输出保护与发现。整套自测不需要
任何第三方 Python 包。

## 目录结构

```
AntPwn/
├── antpwn/            # 核心工具包（纯 Python, 零依赖）
│   ├── elf.py         #   ELF32/ELF64 解析
│   ├── disasm.py      #   x86-32/64 反汇编器（与 objdump 对拍一致）
│   ├── ir.py          #   P-code 风格 IR / CFG / 支配 / 自然循环 / 栈变量
│   ├── decompiler.py  #   结构化反编译（IR → if/else/while → 彩色伪代码）
│   ├── scanner.py     #   漏洞扫描规则引擎
│   ├── gadgets.py     #   ROP gadget 搜索
│   ├── debugger.py    #   ptrace 动态调试器
│   ├── procio.py      #   进程交互 tube
│   ├── aco.py         #   蚁群算法
│   ├── graph.py       #   能力 DAG + 决策树 + 信息素
│   ├── exploits.py    #   8 种利用策略
│   ├── fsm.py         #   解题状态机
│   ├── i18n.py        #   中英双语
│   ├── color.py       #   终端配色（TTY 自动启用）
│   ├── repl.py        #   交互式反汇编/伪代码浏览（view）
│   ├── histedit.py    #   readline 行编辑/历史/补全（可选）
│   ├── report.py      #   HTML 报告
│   └── cli.py         #   命令行入口
├── challenges/        # 8 道原创靶场题（含源码）+ 3 道高级题 + 2 道盲测题
├── antpwn-gdb.py      # gdb 插件加载器（gdb 里 source 这个文件）
├── antpwn/gdb_loader.py # `antpwn-gdb` 命令：打印/写入 .gdbinit 片段
├── pyproject.toml     # pip 安装与 console script（pip install . 后可用 antpwn）
├── .github/workflows/ # test.yml（CI 冒烟+单测）与 release.yml（tag 自动发版）
├── docs/API.md        # 完整 API 文档（模块 / 数据结构 / 扩展示例）
├── docs/API.en.md     # 同上英文版 / English version of the API reference
├── README.en.md       # 英文版 README / English README
└── tests/             # test_core.py 单测 + gdb_smoke.sh（真跑 gdb inferior）+ run_all.py 全量回归
```

## 已知边界 / Limitations

- 静态分析与反编译支持 ELF64 / x86-64 与 ELF32 / i386；32 位利用已覆盖 ret2text、ret2syscall（int 0x80）、shellcode 与 ret2libc 的 cdecl 两阶段链；fmt / heap / SROP / pivot 仅 64 位实现（32 位暂不支持）
- `antpwn_pheromone.json` 是学习产物（按二进制特征向量存边统计），删掉即重置经验
- PIE + 无泄露通道、Full RELRO + 无 fmt/堆、Canary 无泄露等"无解或需高级技巧"场景会
  如实报告失败并给出诊断，不编造可行路径
- **不生成独立的 exploit 脚本或 payload 文本**：payload 在进程内构造与发送；需要复现时
  按报告里的策略与参数自己写脚本
- 远程题需本地有相同 libc（`ldd` 自动定位，或用 `--libc` 显式指定）；远程交互暂不内置（可复用 `antpwn.procio.Tube`）
- canary 爆破只适用于远程 fork 服务，且要求“猜错/猜对”在连接行为上可区分；单次进程不行
- off-by-one / off-by-null 默认只做**检测与打分**；附带一个实验性栈重叠利用
  （`ANTPWN_OFFBYNULL=1` 开启，成功与否取决于栈地址低字节能否落进缓冲区，不保证通用）
- `ret2csu` 在“没有 pop rdi”的二进制上靠 one_gadget 收尾（需要本机装有 `one_gadget`）
- gdb 插件不做 exploit 执行与多连接爆破，远程题仍建议用 CLI；静态链接 / musl 题会被识别成
  「没有 libc 映射」，`plan` 会明确提示这类边界

---

## 许可 / License

MIT —— 见 [LICENSE](LICENSE)。Copyright (c) 2026 guaidao2 & coolmoon。

---

*AntPwn — analysis assistant for CTF pwn: explainable, embeddable, dependency-free. by guaidao2*
