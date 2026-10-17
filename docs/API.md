# AntPwn API 文档

[中文](API.md) | [English](API.en.md)

适用版本：AntPwn v1.3.0
运行环境：Linux / x86-64，Python 3.9+（开发和验证环境为 3.11 与 3.14）
依赖：无第三方包，纯标准库

AntPwn 的 CLI 只是薄壳，所有能力都在 `antpwn` 包里。这份文档按模块列出公开接口、
数据结构和常见用法，方便把 AntPwn 嵌进自己的脚本、平台或比赛工具链。

---

## 目录

1. 快速开始
2. `antpwn.elf` — ELF64 解析与保护识别
3. `antpwn.disasm` — 反汇编器
4. `antpwn.decompiler` — 伪代码还原
5. `antpwn.scanner` — 漏洞扫描
6. `antpwn.gadgets` — ROP gadget 搜索
7. `antpwn.procio` — 进程交互（不挂调试器）
8. `antpwn.debugger` — ptrace 调试器
9. `antpwn.aco` — 蚁群参数搜索
10. `antpwn.graph` — 能力 DAG / 决策树 / 蚁群
11. `antpwn.exploits` — 利用策略与工具函数
12. `antpwn.fsm` — 解题状态机
13. `antpwn.report` — HTML 报告
14. `antpwn.i18n` — 语言控制
15. 典型用法
16. 边界与坑

---

## 1. 快速开始

### 1.1 纯静态分析（不启动目标进程）

```python
from antpwn import ELF, Scanner, Decompiler

elf = ELF("./pwn200")
print("PIE", elf.is_pie, "NX", elf.has_nx, "Canary", elf.canary, "RELRO", elf.relro)

scanner = Scanner(elf)
findings = scanner.scan()            # 已按危险度降序
for f in findings:
    print(f"[{f.kind}] {f.func} @ {f.addr:#x}  {f.text}  score={f.score}")

dc = Decompiler(elf)
pf = dc.function(elf.sym("vuln"))    # 也可以传任意 Symbol
if pf:
    print(dc.render(pf))             # 类 C 伪代码
```

### 1.2 动态交互（管道方式，不挂调试器）

```python
from antpwn import Tube

with Tube("./pwn200") as t:
    t.recv_until(b">")
    t.sendline(b"1")
    t.sendline(b"A" * 200)
    print(t.drain())
```

### 1.3 自动验证一条路线

```python
from antpwn import FSM

fsm = FSM("./pwn200", lang="zh")
ok = fsm.run()
print("result:", fsm.report_data["result"])       # pwned:ret2text / pwned:dag / failed ...
print("steps:", fsm.trace)                        # [(state, event, next_state), ...]
```

### 1.4 崩溃取证：直接拿返回地址偏移

```python
from antpwn import FSM

fsm = FSM("./pwn200")
off = fsm.dt_find_offset()       # None 表示无法判定（无崩溃/证据不足）
print("saved RIP offset:", off)
```

---

## 2. `antpwn.elf` — ELF64 解析与保护识别

```python
from antpwn.elf import ELF, ELFError
elf = ELF(path)                   # 读入整个文件；非 ELF 抛 ELFError
```

只支持 ELF64；32 位二进制会抛 `ELFError("only ELF64 supported in this build")`。

### 属性

| 属性 | 类型 | 说明 |
|---|---|---|
| `path` | str | 文件路径 |
| `data` | bytes | 完整文件内容 |
| `bits` | int | 固定 64 |
| `endian` | str | `<` 或 `>` |
| `e_type` | int | 2=EXEC，3=DYN(PIE) |
| `e_machine` | int | 62 = x86-64 |
| `e_entry` | int | 入口虚拟地址 |
| `phdrs` | list[Phdr] | 程序头 |
| `sections` | list[Section] | 节 |
| `symbols` | list[Symbol] | 符号（已按名字去重，保留首个） |
| `relocs` | list[Reloc] | RELA 重定位 |

### 保护属性（只读 property）

| 属性 | 取值 | 说明 |
|---|---|---|
| `is_pie` | bool | `e_type == 3` |
| `has_nx` | bool | PT_GNU_STACK 无执行位 |
| `has_execstack` | bool | PT_GNU_STACK 可执行 |
| `canary` | bool | 存在 `__stack_chk_fail` 符号 |
| `relro` | `"full"` / `"partial"` / `"none"` | 由 `.dynamic` 的 BIND_NOW 与 PT_GNU_RELRO 共同判定 |

### 方法

| 方法 | 返回 | 说明 |
|---|---|---|
| `section(name)` | Section 或 None | 按节名查找 |
| `sym(name)` | Symbol 或 None | 按符号名查找 |
| `sym_at(va)` | Symbol 或 None | 包含该地址的最内层函数符号 |
| `functions()` | list[Symbol] | 所有 STT_FUNC 且地址非 0 的符号 |
| `data_symbols()` | list[Symbol] | 所有 STT_OBJECT 符号 |
| `got_map()` | dict[str, int] | 符号名 → GOT 槽地址（GLOB_DAT / JUMP_SLOT） |
| `plt_map()` | dict[int, str] | PLT stub 地址 → 符号名 |
| `is_writable(va)` | bool | 是否落在可写 PT_LOAD 段 |
| `read(vaddr, size)` | bytes | 按虚拟地址读文件内容，失败返回 `b""` |
| `vaddr_to_off(vaddr)` | int 或 None | 虚拟地址 → 文件偏移 |
| `strings(minlen=4)` | list[(int, str)] | 从 PT_LOAD 段提取可打印字符串（带虚拟地址） |

### 数据结构

```python
Section: name, type, flags, addr, off, size, data(bytes), link
Symbol:  name, value, size, info, shndx     # value 即虚拟地址
Reloc:   off, info, sym, type               # type 6=GLOB_DAT, 7=JUMP_SLOT
Phdr:    type, flags, off, vaddr, filesz, memsz
```

示例：

```python
elf = ELF("./pwn200")
puts_got = elf.got_map().get("puts")
puts_plt = [a for a, n in elf.plt_map().items() if n == "puts"]
print(hex(puts_got), [hex(a) for a in puts_plt])
if elf.sym("read") and elf.is_writable(0x404000):
    print("usable BSS")
print(elf.strings()[:3])        # [(0x402004, '/bin/sh'), ...]
```

---

## 3. `antpwn.disasm` — 反汇编器

```python
from antpwn.disasm import Disasm, Insn

dis = Disasm(code_bytes, base_addr)
insns = dis.linear(len(code_bytes))            # 线性扫描
insns = dis.recursive(len(code_bytes), [0])    # 递归下降，entries 是起始偏移列表
one = dis.decode_one(offset)                   # 单条，失败返回 None
```

`Insn`：

| 成员 | 说明 |
|---|---|
| `addr` | 虚拟地址 |
| `size` | 指令长度（字节） |
| `mnem` | 助记符，如 `"mov"` / `"call"` / `"leave"` |
| `ops` | 操作数列表，如 `["rdi", "0x10"]` / `["[rbp-0x20]"]` |
| `raw` | 原始字节 |
| `is_ret` / `is_call` / `is_jmp` / `is_jcc` | 指令类别判定（property） |
| `target()` | 直接跳转/调用目标地址；非直接分支返回 None |

覆盖常见 x86-64 指令（含 mov/lea/算术/逻辑/移位/串操作/分支/call/ret/syscall 等），
与 objdump 做过对拍；**不覆盖**全部扩展指令（AVX、部分 SSE、非典型前缀组合）。
遇到无法解码的字节会跳过，`recursive()` 按分支目标继续。

---

## 4. `antpwn.decompiler` — 伪代码还原

```python
from antpwn.decompiler import Decompiler

dc = Decompiler(elf)                  # strings 参数可传入自定义 {vaddr: str}
pf = dc.function(elf.sym("vuln"))     # -> PseudoFunc 或 None
print(dc.render(pf))                  # 渲染成带缩进的类 C 文本
```

`PseudoFunc`：

| 成员 | 说明 |
|---|---|
| `name` / `addr` / `size` | 函数名、地址、大小 |
| `lines` | `[(indent, text), ...]` 伪代码行 |
| `calls` | 调用到的函数名列表（可能带 `@plt`） |
| `stack_vars` | 栈偏移 → 变量名（如 `v0`） |
| `string_refs` | `lea` 目标地址 → 字符串 |
| `effects` | 识别出的副作用，如 `("backdoor_shell", ...)` |

`render(pf)` 返回字符串，可直接打印或写进报告。

---

## 5. `antpwn.scanner` — 漏洞扫描

```python
from antpwn.scanner import Scanner

scanner = Scanner(elf)
findings = scanner.scan()        # list[Finding]，按 score 降序
scanner.funcs                    # {函数名: PseudoFunc}
scanner.summary()                # Counter({kind: 数量})
```

`Finding`：

| 成员 | 说明 |
|---|---|
| `kind` | 类型，见下表 |
| `func` | 所在函数名（字符串类为 `.rodata` 等） |
| `addr` | 虚拟地址 |
| `detail` | 中文/英文文案（元组或字符串） |
| `text` | 按当前语言返回可读文案（property） |
| `score` | 危险度评分，越大越危险 |
| `evidence` | 证据片段，如 `call gets()` |

`kind` 取值：

| kind | 含义 | 典型分 |
|---|---|---|
| `bof` | 栈缓冲区溢出 | 10 |
| `backdoor` | 后门函数 | 10 / 7 |
| `fmt` | 格式化字符串 | 9 |
| `flag` | 疑似 flag 字符串 | 9 |
| `heap` | UAF / double-free 线索 | 8 |
| `exec_stack` | 栈可执行 | 8 |
| `no_canary` / `no_pie` | 保护缺失 | 5 / 4 |
| `sh_string` | `/bin/sh` 等字符串 | 3 |
| `danger` | 其他危险函数调用 | 见 `DANGER` |

注意：规则引擎是启发式的，给的是「线索 + 打分」，不是证明。判断路线时仍要结合保护、
gadget 与动态验证（`FSM.run()` 就是干这个的）。

---

## 6. `antpwn.gadgets` — ROP gadget 搜索

```python
from antpwn.gadgets import GadgetFinder, Gadget

gf = GadgetFinder(elf)
gadgets = gf.find_all()            # {name: [Gadget, ...]}
rdi = gf.first("pop rdi")          # 第一个 pop rdi 的地址，找不到返回 None
get = gf.rop_chain_builder()       # get("pop rdi") -> addr，缺失时抛 KeyError
```

可查的名字（`WANT` 表）：`pop rdi`、`pop rsi`、`pop rdx`、`pop rax`、`pop rbp`、
`ret`、`leave;ret`、`syscall`、`syscall;ret`、`jmp rsp`、`call rsp`、
`pop rdi;pop rbp`、`pop rsi;pop r15`。

`Gadget`：`addr`、`insns`（指令文本列表）、`effect`（描述）。

这是**定向扫描**（在可执行段里搜固定字节模式），不是全量 gadget 数据库：
只覆盖常见入口，够 AntPwn 自己的 8 种策略用。要全面的 gadget 列表请配合 ROPgadget。

---

## 7. `antpwn.procio` — 进程交互（不挂调试器）

```python
from antpwn.procio import Tube

t = Tube(path, argv=None, env=None)     # 子进程管道；stderr 合并到 stdout
with Tube(path) as t:
    ...
```

| 方法 | 返回 | 说明 |
|---|---|---|
| `send(data)` | - | str 自动 encode |
| `sendline(data=b"")` | - | 追加换行 |
| `recv(timeout=1.0, size=4096)` | bytes | 超时返回 `b""` |
| `recv_until(marker, timeout=3.0)` | bytes | 读到 marker 或超时（超时返回已读内容） |
| `clean(timeout=0.3)` | bytes | 清空当前缓冲 |
| `drain(idle=0.4, max_total=2_000_000)` | bytes | 一直读到管道安静；防止 `%Nc` 大输出把 64KB 管道写满后子进程卡死 |
| `alive()` | bool | 进程是否还在 |
| `interactive_cmds(cmds, timeout=1.5)` | bytes | 依次发送命令并收集输出（找 flag 用） |
| `close()` | - | 杀进程 |

`Tube` 用于正常 I/O；要看崩溃现场（寄存器/内存）用下一节的 `Process`。

---

## 8. `antpwn.debugger` — ptrace 调试器

```python
from antpwn.debugger import Process

p = Process(path, argv=None, envp=None)
p.start()                    # fork + TRACEME + exec，停在 exec trap
p.send(b"A" * 100 + b"\n")
p.close_stdin()              # 发 EOF，避免阻塞读把等待拖死
ev = p.cont(timeout=1.5)     # -> (kind, code)
if ev[0] in ("stop", "trap"):
    regs = p.getregs()
    print(hex(regs.rip), hex(regs.rsp))
p.kill()
```

### 生命周期

| 方法 | 说明 |
|---|---|
| `start(entry_bp=False, quiet=True)` | 启动并停在 exec trap；`quiet=True` 时子进程 stdout/stderr 重定向到 `/dev/null`（只看崩溃现场时用） |
| `cont(timeout=None)` | PTRACE_CONT 后轮询 waitpid |
| `step()` | 单步 |
| `kill()` | SIGKILL 并回收 |
| `send(data)` / `close_stdin()` | 写 stdin / 关闭 stdin |

### `cont()` 返回值

| 元组 | 含义 |
|---|---|
| `("trap", 0)` | SIGTRAP（断点或 exec/单步） |
| `("stop", sig)` | 收到其他信号停下，`sig` 是信号号 |
| `("exit", code)` | 正常退出 |
| `("killed", sig)` | 被信号杀死 |
| `("timeout", 0)` | 轮询超时（子进程可能停在读输入） |

### 寄存器与内存

```python
regs = p.getregs()          # Regs 结构，字段见下
p.setregs(regs)
p.peek(addr)                # 读 8 字节（int）
p.poke(addr, value)         # 写 8 字节
p.read_mem(addr, size)      # -> bytes
p.write_mem(addr, data)     # 写任意长度（不足 8 字节自动补齐）
```

`Regs` 字段：`r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi
orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs`。

### 断点与辅助

| 方法 | 说明 |
|---|---|
| `bp(addr)` | 下软件断点（记录原字节并写 `0xCC`） |
| `hit(addr)` | SIGTRAP 后调用：判断命中对应断点、恢复并单步重设 |
| `wait_bp(addr, timeout_loops=200000)` | 继续执行直到命中该断点 |
| `mmap_base()` | 读 `/proc/<pid>/maps` 取可执行映射基址（PIE 的加载基址） |
| `find_libc()` | 从 maps 里找 libc 路径 |
| `maps()` | 解析 `/proc/<pid>/maps` |

### 注意

- 仅 Linux；依赖 `libc.so.6` 与 ptrace 权限（普通用户对自己的子进程即可）。
- 默认 `envp` 只有 `PATH` 和 `HOME=/home/z`：需要其他环境变量（如 `LD_PRELOAD`）时
  自己构造 `envp` 传入。
- `quiet=True` 丢弃输出，所以别用 `Process` 做需要读程序提示的交互，那个用 `Tube`。

---

## 9. `antpwn.aco` — 蚁群参数搜索

```python
from antpwn.aco import AntColony, OffsetColony

dims = [list(range(16, 256, 8))]          # 每个维度是一组候选值

def fitness(vals):
    off = vals[0]
    ...                                    # 返回 0.0 ~ 1.0
    return score

colony = AntColony(dims, fitness, ants=24, iters=30, seed=None)
best, score = colony.run(on_iter=lambda it, k, vals, s: print(it, k, vals, s))
```

| 参数 | 说明 |
|---|---|
| `dims` | 候选值列表的列表，一个维度一组 |
| `fitness(trail)` | 把「选中的值组合」映射成 [0,1] 分数 |
| `ants` / `iters` | 每轮蚂蚁数 / 迭代轮数 |
| `evap` / `alpha` / `beta` | 信息素蒸发率、信息素权重、启发式权重 |
| `seed` | 随机种子，固定后结果可复现 |

`run()` 返回 `(best_vals, best_score)`；命中 1.0 会提前收敛。`colony.history` 是每轮
最优分。`on_iter(it, k, vals, score)`：`k >= 0` 表示单只蚂蚁，`k == -1` 表示该轮结束。

`OffsetColony(make_payload, check, lo=64, hi=200, step=8)` 是偏移搜索的特化：
`check(off)` 返回分数；`make_payload(off)` 用于构造探测输入。

注意：AntPwn 的 FSM 现在优先用「崩溃取证 + 决策树」定偏移（一次崩溃直接反解），
ACO 是证据不足时的兜底，函数是 `FSM.find_offset(strategy)`。

---

## 10. `antpwn.graph` — 能力 DAG / 决策树 / 蚁群

这一层是 AntPwn 的决策核心：把「拿 shell」拆成若干能力节点，技术是边；蚂蚁沿边
前进，失败留下的能力（session 域）给下一只复用。

### 能力常量

```python
SESSION = "session"     # 跨进程有效（偏移、fmt 参数位置）
PROCESS = "process"     # 只在当前进程内有效（libc 基址、堆布局）

CAP_RIP   = "rip_control"
CAP_LIBC  = "libc_base"
CAP_FMTK  = "fmt_k"
CAP_HEAP  = "heap_layout"
CAP_WRITE = "write_prim"
CAP_SHELL = "shell"
```

### `Technique` — 一条边

```python
Technique(name, requires, provides, execute,
          feasible=None, scope=SESSION, prio=5, zh="", en="", preamble=None)
```

| 参数 | 说明 |
|---|---|
| `name` | 技术名（也会写进信息素统计） |
| `requires` | 前置能力集合 |
| `provides` | 能提供的能力集合 |
| `execute(ctx)` | 执行体，返回 True 表示成功入账 |
| `feasible(ctx)` | 确定性可行谓词（决策树的分裂条件） |
| `scope` | 提供的能力属于 session 还是 process 域 |
| `prio` | 专家先验优先级（数字越小越先，信息素攒够后可被覆盖） |
| `zh` / `en` | 日志用的人话描述 |
| `preamble` | 多段读程序里，该技术对应的输入流前缀 |

### `DecisionTree`

- `features(ctx)` -> dict：从上下文提取观测特征（漏洞类型、保护、gadget、已获能力）
- `certified(ctx, edges)` -> list[Technique]：滤掉前置不满足、不可行、能力已全部持有的边

### `Colony`

```python
from antpwn.graph import Colony

colony = Colony(edges, log, phero_path="antpwn_pheromone.json")
trail, ok = colony.solve(ctx, waves=4, ants_per_wave=2)
```

| 方法 | 说明 |
|---|---|
| `solve(ctx, waves=4, ants_per_wave=2)` | 多波蚂蚁；成功返回 `(trail, True)`，否则 `(None, False)` |
| `walk(ctx, budget=14)` | 单只蚂蚁，返回 `(trail, ok, session_gained)` |
| `choose(ctx, cands)` | 决策树认证后，按信息素胜率 + 专家先验排序（10% 探索） |

`trail` 是 `[(Technique, ok), ...]`。信息素按「二进制特征签名 → 边 → [wins, tries]」
存进 `phero_path`（默认当前目录的 `antpwn_pheromone.json`），删除即重置经验。
两个进程同时跑同一个 phero 文件没有加锁，可能互相覆盖。

### 扩展：加一门技术

```python
from antpwn.graph import Technique, CAP_RIP, CAP_SHELL, SESSION, Colony
from antpwn.fsm import Logger

def execute(ctx):
    ...                     # 自己构造并发送，成功返回 True
    return True

my_edge = Technique(
    "my-chain", requires={CAP_RIP}, provides={CAP_SHELL},
    execute=execute,
    feasible=lambda c: "bof" in c.vuln_kinds,
    scope=SESSION, prio=8, zh="自定义链", en="custom chain")

edges = fsm.build_edges(ctx) + [my_edge]
colony = Colony(edges, Logger())
trail, ok = colony.solve(ctx)
```

---

## 11. `antpwn.exploits` — 利用策略与工具函数

### 工具函数

```python
from antpwn.exploits import cyclic, cyclic_find, find_libc, libc_offsets
from antpwn.exploits import scan_libc_ptr, p64, u64, SHELLCODE, SHELL_RESP

pattern = cyclic(200)             # 循环模式，用于算返回地址偏移
idx = cyclic_find(pattern[72:80]) # 从崩溃值反查偏移
path, libc = find_libc("./pwn")   # 用 ldd 定位目标 libc，返回 (path, ELF)
offs = libc_offsets(libc)         # {"puts":..., "system":..., "free":..., "/bin/sh":...}
res = scan_libc_ptr(leaked, offs["puts"])   # -> (leaked_ptr, libc_base) 或 None
p64(0x401234)                     # 8 字节小端打包
```

常量：`SHELLCODE`（23 字节 execve shellcode）、`SHELL_MARKER` / `SHELL_RESP`
（验证 shell 用的指令与回显标记）。

### `ExploitContext`

FSM 与各策略共享的状态：

| 成员 | 说明 |
|---|---|
| `elf` / `scanner` / `gadgets` / `log` | 上游对象 |
| `offset` | 当前策略使用的返回地址偏移 |
| `libc_path` / `libc` / `libc_off` | libc 路径、ELF、偏移表 |
| `fmt_k` | 格式化字符串参数位置 |
| `heap_leak` | 堆泄露信息 |
| `notes` | 人话解释 `[(zh, en)]`，会进报告 |
| `capabilities` | 已获能力集合（DAG 黑板） |
| `live` | 进程域状态（tube、libc 基址、chunk 等） |
| `offsets_map` | 输入流前缀 → 偏移 |

辅助判定：`vuln_kinds`、`has_binsh`、`has_rop_gadgets`、`has_leak_function`、
`bof_finding()`、`bof_func_addr()`、`bof_is_line_input()`、`backdoor_addr()`。
这些都是**行为判定**（看是不是真的调用 `system("/bin/sh")`），不依赖函数名。

### 策略类

所有策略继承 `Strategy`，实现 `feasible()` 与 `run()`，`run()` 返回 bool：

| 类 | 技术 |
|---|---|
| `Ret2Text` | 跳后门函数 |
| `Ret2Libc` | 泄露 puts → 算基址 → 二次返回 system |
| `Ret2Syscall` | ROP 链 execve |
| `FmtGOT` | 格式化字符串（有后门 %hn / 无后门 %s 泄 libc） |
| `Shellcode` | 可执行栈注入 |
| `SROP` | sigreturn 帧 |
| `StackPivot` | 栈迁移 |
| `HeapUAF` | tcache poisoning |

`ALL_STRATEGIES` 是上述 8 个类的列表。单独调用示例：

```python
from antpwn import ELF, Scanner, GadgetFinder
from antpwn.exploits import ExploitContext, Ret2Text
from antpwn.fsm import Logger

ctx = ExploitContext(ELF("./pwn"), Scanner(ELF("./pwn")), GadgetFinder(ELF("./pwn")), Logger())
ctx.offset = 72
print(Ret2Text(ctx).feasible())
print(Ret2Text(ctx).run())
```

---

## 12. `antpwn.fsm` — 解题状态机

```python
from antpwn.fsm import FSM, State, Logger

fsm = FSM(path, log=None, lang="zh")
ok = fsm.run()
```

### 运行

`run()` 顺序：RECON → DECOMPILE → SCAN → STRATEGY（能力 DAG + 蚁群）→
失败则回退到旧线性策略表 → 成功进 VERIFY。返回 `True` 表示拿到 shell。

### 属性

| 属性 | 说明 |
|---|---|
| `state` | 当前状态（`State.*`） |
| `trace` | `[(cur, event, next), ...]` 状态迁移记录 |
| `report_data` | 报告数据，见下 |
| `log` | `Logger`（`records` 保存所有日志行） |
| `elf` / `scanner` / `ctx` | 分析对象与共享上下文 |

`report_data` 的键：

```
path, mitigations{pix,nx,canary,relro,execstack,arch}, functions[],
findings[], strategies[], offset, aco[], notes[], result, steps[]
```

`result` 取值：`pwned:dag` / `pwned:<strategy>` / `failed` / `not_elf`。

### 偏移推断相关

| 方法 | 说明 |
|---|---|
| `dt_find_offset(preamble=b"")` | 崩溃取证：一次崩溃反解 cyclic 模式，再用 marker 验证；None 表示无法判定 |
| `find_offset(strategy)` | ACO 兜底搜索（内部会先做崩溃性预检） |
| `crash_score(off, marker, preamble=b"")` | 返回 RIP 控制度 0.0 ~ 1.0 |
| `static_buf_estimate()` | 从 `sub rsp,N` / `[rbp-N]` 估缓冲区大小 |
| `build_edges(ctx)` | 构造内置的能力 DAG 边列表（自定义扩展时用） |

### 状态常量

`State.RECON / DECOMPILE / SCAN / STRATEGY / OFFSET / BUILD / TEST / VERIFY / DONE / FAILED`

### 日志

```python
from antpwn.fsm import Logger

log = Logger(verbose=False)      # 不打印，只收集
fsm = FSM(path, log=log)
fsm.run()
print("\n".join(log.records))
```

---

## 13. `antpwn.report` — HTML 报告

```python
from antpwn.report import save_report

path = save_report(fsm, "out.html")     # 返回实际写入路径
```

报告内容：保护状态、函数表、漏洞发现（带评分）、策略路线、ACO 记录、人话解释、结果。
中文/英文随 `fsm` 的语言设置。

---

## 14. `antpwn.i18n` — 语言控制

```python
from antpwn import i18n

i18n.set_lang("en")        # "zh" / "en"，None 表示不改变
print(i18n.t("recon"))     # 取文案；未知 key 原样返回
```

语言是模块级全局状态，会影响 `Finding.text`、日志、报告。

---

## 15. 典型用法

### 15.1 批量扫描一个目录（只静态分析）

```python
from pathlib import Path
from antpwn import ELF, Scanner

for p in sorted(Path("challenges").rglob("*")):
    if not p.is_file():
        continue
    try:
        elf = ELF(str(p))
    except Exception:
        continue
    fs = Scanner(elf).scan()
    top = fs[0]
    print(f"{p.name:24} PIE={elf.is_pie!s:5} NX={elf.has_nx!s:5} "
          f"top={top.kind}/{top.score}")
```

### 15.2 拿保护信息做自己的决策

```python
elf = ELF(target)
has_pop_rdi = "pop rdi" in GadgetFinder(elf).find_all()
risky = (elf.is_pie or elf.canary) and not elf.has_nx
```

### 15.3 自己起进程、自己发 payload，只借用崩溃分析

```python
from antpwn.debugger import Process
from antpwn.exploits import cyclic, p64

p = Process(target)
p.start()
p.send(cyclic(200) + b"\n")
p.close_stdin()
ev = p.cont(timeout=1.5)
regs = p.getregs()
print(ev, hex(regs.rip))
p.kill()
```

### 15.4 用 ACO 搜别的参数

```python
from antpwn.aco import AntColony

# 例：fmt 参数位置搜索
dims = [list(range(1, 41))]
colony = AntColony(dims, fitness=lambda v: 1.0 if probe(v[0]) else 0.0,
                   ants=8, iters=6, seed=1)
best, score = colony.run()
```

### 15.5 只跑单条策略、不要整套 FSM

见 11 节的 `ExploitContext` + `Ret2Text(ctx).run()`。这适合你已经知道要走哪条路线，
只想复用 AntPwn 的探测与发送逻辑。

---

## 16. 边界与坑

- **平台**：仅 Linux x86-64；`debugger` 在 import 时就加载 `libc.so.6`，Windows/macOS
  上连 `import antpwn` 都会失败。
- **32 位**：`ELF` 会抛 `ELFError`，整套分析按 x86-64 设计。
- **全局状态**：`i18n.LANG` 是模块级变量，多线程/多任务并发时语言会互相影响。
- **信息素文件**：默认写当前工作目录的 `antpwn_pheromone.json`；无锁，并发跑会互相覆盖；
  测试/CI 里建议显式传 `phero_path` 或跑前删除，保证结果可复现。
- **`Process` 默认静音**：`quiet=True` 时子进程 stdout/stderr 进 `/dev/null`；需要读输出用
  `Tube`，需要看崩溃现场用 `Process`。
- **`find_libc` 依赖 `ldd`**：远程题要求本地有同一版本 libc；没有 `ldd` 的环境会失败。
- **扫描是启发式**：`score` 只是排序优先级，不是结论；最终以 `FSM.run()` 的动态验证为准。
- **API 稳定性**：v1.x 内以本文档列出的公开成员为准；下划线开头的方法/属性是内部实现，
  可能随版本调整。
