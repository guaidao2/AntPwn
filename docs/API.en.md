# AntPwn API Reference

[中文](API.md) | **English**

Version: AntPwn v1.6.1
Platform: Linux / x86-64, Python 3.9+ (developed and verified on 3.11 and 3.14)
Dependencies: none (standard library only)

The AntPwn CLI is a thin shell; all functionality lives in the `antpwn` package. This document
lists the public interfaces, data structures and common recipes, so that AntPwn can be embedded
into your scripts, platform or CTF toolchain.

---

## Contents

1. Quick start
2. `antpwn.elf` — ELF64 parsing and mitigation detection
3. `antpwn.disasm` — disassembler
4. `antpwn.decompiler` — pseudo-code recovery
5. `antpwn.scanner` — vulnerability scanning
6. `antpwn.gadgets` — ROP gadget search
7. `antpwn.procio` — process interaction (no debugger attached)
8. `antpwn.debugger` — ptrace debugger
9. `antpwn.aco` — ant colony parameter search
10. `antpwn.graph` — capability DAG / decision tree / colony
11. `antpwn.exploits` — strategies and helpers
12. `antpwn.fsm` — solver state machine
13. `antpwn.report` — HTML report
14. `antpwn.i18n` — language control
15. Recipes
16. Boundaries and pitfalls
17. `antpwn.color` — terminal colour styling
18. `antpwn.repl` — interactive browser (r2-style)
19. Packaging, tests and CI
20. `antpwn.gdbplugin` — the gdb plugin

---

## 1. Quick start

### 1.1 Static analysis only (no target process)

```python
from antpwn import ELF, Scanner, Decompiler

elf = ELF("./pwn200")
print("PIE", elf.is_pie, "NX", elf.has_nx, "Canary", elf.canary, "RELRO", elf.relro)

scanner = Scanner(elf)
findings = scanner.scan()            # sorted by severity, descending
for f in findings:
    print(f"[{f.kind}] {f.func} @ {f.addr:#x}  {f.text}  score={f.score}")

dc = Decompiler(elf)
pf = dc.function(elf.sym("vuln"))    # any Symbol works
if pf:
    print(dc.render(pf))             # C-like pseudo-code
```

### 1.2 Process interaction (pipes, no debugger)

```python
from antpwn import Tube

with Tube("./pwn200") as t:
    t.recv_until(b">")
    t.sendline(b"1")
    t.sendline(b"A" * 200)
    print(t.drain())
```

### 1.3 Verify a route automatically

```python
from antpwn import FSM

fsm = FSM("./pwn200", lang="zh")
ok = fsm.run()
print("result:", fsm.report_data["result"])       # pwned:ret2text / pwned:dag / failed ...
print("steps:", fsm.trace)                        # [(state, event, next_state), ...]
```

### 1.4 Crash forensics: get the saved return-address offset directly

```python
from antpwn import FSM

fsm = FSM("./pwn200")
off = fsm.dt_find_offset()       # None when undecidable (no crash / weak evidence)
print("saved RIP offset:", off)
```

---

## 2. `antpwn.elf` — ELF64 parsing and mitigation detection

```python
from antpwn.elf import ELF, ELFError
elf = ELF(path)                   # reads the whole file; raises ELFError if not ELF
```

ELF64 only; 32-bit binaries raise `ELFError("only ELF64 supported in this build")`.

### Attributes

| Attribute | Type | Description |
|---|---|---|
| `path` | str | file path |
| `data` | bytes | full file content |
| `bits` | int | fixed at 64 |
| `endian` | str | `<` or `>` |
| `e_type` | int | 2=EXEC, 3=DYN (PIE) |
| `e_machine` | int | 62 = x86-64 |
| `e_entry` | int | entry virtual address |
| `phdrs` | list[Phdr] | program headers |
| `sections` | list[Section] | sections |
| `symbols` | list[Symbol] | symbols (deduplicated by name, first kept) |
| `relocs` | list[Reloc] | RELA relocations |

### Mitigation attributes (read-only properties)

| Attribute | Value | Description |
|---|---|---|
| `is_pie` | bool | `e_type == 3` |
| `has_nx` | bool | PT_GNU_STACK without the executable bit |
| `has_execstack` | bool | PT_GNU_STACK executable |
| `canary` | bool | `__stack_chk_fail` symbol present |
| `relro` | `"full"` / `"partial"` / `"none"` | derived from BIND_NOW in `.dynamic` plus PT_GNU_RELRO |

### Methods

| Method | Returns | Description |
|---|---|---|
| `section(name)` | Section or None | look up by section name |
| `sym(name)` | Symbol or None | look up by symbol name |
| `sym_at(va)` | Symbol or None | innermost function symbol containing the address |
| `functions()` | list[Symbol] | all STT_FUNC symbols with a non-zero address |
| `data_symbols()` | list[Symbol] | all STT_OBJECT symbols |
| `got_map()` | dict[str, int] | symbol name → GOT slot (GLOB_DAT / JUMP_SLOT) |
| `plt_map()` | dict[int, str] | PLT stub address → symbol name |
| `is_writable(va)` | bool | whether the address is inside a writable PT_LOAD |
| `read(vaddr, size)` | bytes | read file content by virtual address, `b""` on failure |
| `vaddr_to_off(vaddr)` | int or None | virtual address → file offset |
| `strings(minlen=4)` | list[(int, str)] | printable strings from PT_LOAD segments, with virtual addresses |
| `exec_segments()` | generator[(int, bytes)] | executable PT_LOAD segments (address + bytes) |
| `discovered_functions(max_bytes=0x100000)` | list[Symbol] | heuristic discovery for stripped binaries: entry + recursive call targets + prologue patterns, named `sub_<addr>` |
| `code_symbols()` | list[Symbol] | real symbols when available, else the heuristic discovery; used by `Scanner` and `view` |

### Data structures

```python
Section: name, type, flags, addr, off, size, data(bytes), link
Symbol:  name, value, size, info, shndx     # value is the virtual address
Reloc:   off, info, sym, type               # type 6=GLOB_DAT, 7=JUMP_SLOT
Phdr:    type, flags, off, vaddr, filesz, memsz
```

Example:

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

## 3. `antpwn.disasm` — disassembler

```python
from antpwn.disasm import Disasm, Insn

dis = Disasm(code_bytes, base_addr)
insns = dis.linear(len(code_bytes))            # linear sweep
insns = dis.recursive(len(code_bytes), [0])    # recursive descent, entries = start offsets
one = dis.decode_one(offset)                   # single instruction, None on failure
```

`Insn`:

| Member | Description |
|---|---|
| `addr` | virtual address |
| `size` | instruction length in bytes |
| `mnem` | mnemonic, e.g. `"mov"`, `"call"`, `"leave"` |
| `ops` | operand list, e.g. `["rdi", "0x10"]`, `["[rbp-0x20]"]` |
| `raw` | raw bytes |
| `is_ret` / `is_call` / `is_jmp` / `is_jcc` | instruction class predicates (properties) |
| `target()` | direct branch/call target; None for indirect branches |

Common x86-64 instructions are covered (mov/lea/arithmetic/logic/shifts/string ops/branches/
call/ret/syscall and more) and cross-checked against objdump. It does **not** cover every
extension (AVX, some SSE, uncommon prefix combinations). Undecodable bytes are skipped and
`recursive()` continues from branch targets.

---

## 4. `antpwn.decompiler` — pseudo-code recovery

```python
from antpwn.decompiler import Decompiler

dc = Decompiler(elf)                  # optional strings={vaddr: str}
pf = dc.function(elf.sym("vuln"))     # -> PseudoFunc or None
print(dc.render(pf))                  # indented C-like text
```

`PseudoFunc`:

| Member | Description |
|---|---|
| `name` / `addr` / `size` | function name, address, size |
| `lines` | `[(indent, text), ...]` pseudo-code lines |
| `calls` | called function names (may include `@plt`) |
| `stack_vars` | stack offset → variable name (e.g. `v0`) |
| `string_refs` | `lea` target address → string |
| `effects` | detected side effects, e.g. `("backdoor_shell", ...)` |

`render(pf)` returns a string, ready to print or embed in a report.

---

## 5. `antpwn.scanner` — vulnerability scanning

```python
from antpwn.scanner import Scanner

scanner = Scanner(elf)
findings = scanner.scan()        # list[Finding], ordered by score descending
scanner.funcs                    # {function name: PseudoFunc}
scanner.summary()                # Counter({kind: count})
```

`Finding`:

| Member | Description |
|---|---|
| `kind` | type, see the table below |
| `func` | containing function (`.rodata` etc. for string findings) |
| `addr` | virtual address |
| `detail` | zh/en strings (tuple or str) |
| `text` | readable text in the current language (property) |
| `score` | severity score, higher is worse |
| `evidence` | evidence snippet, e.g. `call gets()` |

`kind` values:

| kind | Meaning | Typical score |
|---|---|---|
| `bof` | stack buffer overflow | 10 |
| `backdoor` | backdoor function | 10 / 7 |
| `fmt` | format string | 9 |
| `flag` | possible flag string | 9 |
| `heap` | UAF / double-free hint | 8 |
| `exec_stack` | executable stack | 8 |
| `no_canary` / `no_pie` | missing mitigation | 5 / 4 |
| `sh_string` | `/bin/sh`-style string | 3 |
| `danger` | other dangerous call | see `DANGER` |

The rule engine is heuristic: it produces leads plus a score, not proof. Route selection still
combines mitigations, gadgets and dynamic verification (`FSM.run()` does exactly that).

### Buffer/length correlation (simplified dataflow)

The scanner reads the rendered pseudo-code and correlates stack buffer declarations
(`char v0[64];`) with input lengths: `read(0, v0, 0x12c)` reports the exact overflow size
(score=10), `size == buf+1` is reported as off-by-one (score=9), and width-limited
`scanf("%63s", v0)` is not flagged. The evidence lands in `Finding.evidence` and is shown by
`view vuln` and the HTML report.

---

## 6. `antpwn.gadgets` — ROP gadget search

```python
from antpwn.gadgets import GadgetFinder, Gadget

gf = GadgetFinder(elf)
gadgets = gf.find_all()            # {name: [Gadget, ...]}
rdi = gf.first("pop rdi")          # address of the first pop rdi, None if absent
get = gf.rop_chain_builder()       # get("pop rdi") -> addr, raises KeyError if missing
```

Available names (`WANT` table): `pop rdi`, `pop rsi`, `pop rdx`, `pop rax`, `pop rbp`, `ret`,
`leave;ret`, `syscall`, `syscall;ret`, `jmp rsp`, `call rsp`, `pop rdi;pop rbp`,
`pop rsi;pop r15`.

`Gadget`: `addr`, `insns` (list of instruction texts), `effect` (description).

This is a **targeted scan** (fixed byte patterns inside executable segments), not a full gadget
database: it covers the common entries AntPwn's own strategies need. For a complete gadget list
use ROPgadget alongside it.

---

## 7. `antpwn.procio` — process interaction (no debugger)

```python
from antpwn.procio import Tube

t = Tube(path, argv=None, env=None)     # pipe-based child; stderr merged into stdout
with Tube(path) as t:
    ...
```

| Method | Returns | Description |
|---|---|---|
| `send(data)` | - | str is encoded automatically |
| `sendline(data=b"")` | - | appends a newline |
| `recv(timeout=1.0, size=4096)` | bytes | `b""` on timeout |
| `recv_until(marker, timeout=3.0)` | bytes | reads until marker or timeout (returns what was read) |
| `clean(timeout=0.3)` | bytes | drain the current buffer |
| `drain(idle=0.4, max_total=2_000_000)` | bytes | read until the pipe goes quiet; prevents a child from blocking when `%Nc` padding exceeds the 64KB pipe buffer |
| `alive()` | bool | whether the process is still running |
| `interactive_cmds(cmds, timeout=1.5)` | bytes | send commands in order and collect output (flag hunting) |
| `close()` | - | kill the process |

`Tube` is for normal I/O; to inspect a crash site (registers/memory) use `Process` below.

### `RemoteTube` — remote targets

Same interface as `Tube`, backed by a TCP socket (`antpwn/procio.py`):

```python
from antpwn.procio import RemoteTube

t = RemoteTube("10.0.0.1", 1337)   # connect to the service directly
t.sendline(b"1")
print(t.recv_until(b">"))
t.close()
```

| Method | Description |
|---|---|
| `send` / `sendline` / `recv` / `recv_until` / `clean` / `drain` | same semantics as `Tube` |
| `alive()` | whether the socket is still alive (MSG_PEEK probe) |
| `interactive_cmds(cmds)` | send commands in order and collect output |
| `close()` | shutdown + close |

`pwn --remote HOST:PORT` makes `ExploitContext.new_tube()` return a `RemoteTube`; all
strategies are shared with local mode.

---

## 8. `antpwn.debugger` — ptrace debugger

```python
from antpwn.debugger import Process

p = Process(path, argv=None, envp=None)
p.start()                    # fork + TRACEME + exec, stopped at the exec trap
p.send(b"A" * 100 + b"\n")
p.close_stdin()              # send EOF so a blocking read does not stall the wait
ev = p.cont(timeout=1.5)     # -> (kind, code)
if ev[0] in ("stop", "trap"):
    regs = p.getregs()
    print(hex(regs.rip), hex(regs.rsp))
p.kill()
```

### Lifecycle

| Method | Description |
|---|---|
| `start(entry_bp=False, quiet=True)` | start and stop at the exec trap; `quiet=True` redirects child stdout/stderr to `/dev/null` (crash-site inspection only) |
| `cont(timeout=None)` | PTRACE_CONT then poll waitpid |
| `step()` | single step |
| `kill()` | SIGKILL and reap |
| `send(data)` / `close_stdin()` | write stdin / close stdin |

### `cont()` return values

| Tuple | Meaning |
|---|---|
| `("trap", 0)` | SIGTRAP (breakpoint, exec or single step) |
| `("stop", sig)` | stopped by another signal, `sig` is the signal number |
| `("exit", code)` | normal exit |
| `("killed", sig)` | killed by a signal |
| `("timeout", 0)` | poll timed out (child may be blocked on input) |

### Registers and memory

```python
regs = p.getregs()          # Regs structure, fields below
p.setregs(regs)
p.peek(addr)                # read 8 bytes (int)
p.poke(addr, value)         # write 8 bytes
p.read_mem(addr, size)      # -> bytes
p.write_mem(addr, data)     # arbitrary length (padded to 8 bytes)
```

`Regs` fields: `r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs
eflags rsp ss fs_base gs_base ds es fs gs`.

### Breakpoints and helpers

| Method | Description |
|---|---|
| `bp(addr)` | set a software breakpoint (saves the original bytes, writes `0xCC`) |
| `hit(addr)` | call after SIGTRAP: detect the hit, restore, single-step and re-arm |
| `wait_bp(addr, timeout_loops=200000)` | continue until the breakpoint is hit |
| `mmap_base()` | read `/proc/<pid>/maps` to get the executable mapping base (PIE load base) |
| `find_libc()` | locate the libc path from maps |
| `maps()` | parse `/proc/<pid>/maps` |

### Notes

- Linux only; requires `libc.so.6` and ptrace permission (a normal user can trace its own children).
- The default `envp` contains only `PATH` and `HOME=/home/z`: build your own `envp` when you
  need other variables (e.g. `LD_PRELOAD`).
- `quiet=True` discards output, so do not use `Process` for prompts you need to read; use `Tube`.

---

## 9. `antpwn.aco` — ant colony parameter search

```python
from antpwn.aco import AntColony, OffsetColony

dims = [list(range(16, 256, 8))]          # one candidate list per dimension

def fitness(vals):
    off = vals[0]
    ...                                    # return a score in [0.0, 1.0]
    return score

colony = AntColony(dims, fitness, ants=24, iters=30, seed=None)
best, score = colony.run(on_iter=lambda it, k, vals, s: print(it, k, vals, s))
```

| Parameter | Description |
|---|---|
| `dims` | list of candidate lists, one per dimension |
| `fitness(trail)` | maps a chosen value combination to a score in [0,1] |
| `ants` / `iters` | ants per iteration / iterations |
| `evap` / `alpha` / `beta` | evaporation rate, pheromone weight, heuristic weight |
| `seed` | random seed, fixed seed makes results reproducible |

`run()` returns `(best_vals, best_score)`; reaching 1.0 converges early. `colony.history` holds
the best score per iteration. `on_iter(it, k, vals, score)`: `k >= 0` is a single ant,
`k == -1` marks the end of an iteration.

`OffsetColony(make_payload, check, lo=64, hi=200, step=8)` specialises this for offset search:
`check(off)` returns the score, `make_payload(off)` builds the probe input.

Note: AntPwn's FSM now prefers crash forensics plus the decision tree for offsets (one crash
gives the answer directly); ACO is the fallback when evidence is inconclusive. The entry point
is `FSM.find_offset(strategy)`.

---

## 10. `antpwn.graph` — capability DAG / decision tree / colony

This is AntPwn's decision core: "get a shell" is split into capability nodes, techniques are
edges; ants walk edges and capabilities left behind by failed ants (session scope) are reused
by the next ant.

### Capability constants

```python
SESSION = "session"     # valid across processes (offset, fmt argument index)
PROCESS = "process"     # valid only inside the current process (libc base, heap layout)

CAP_RIP   = "rip_control"
CAP_LIBC  = "libc_base"
CAP_FMTK  = "fmt_k"
CAP_HEAP  = "heap_layout"
CAP_WRITE = "write_prim"
CAP_SHELL = "shell"
```

### `Technique` — one edge

```python
Technique(name, requires, provides, execute,
          feasible=None, scope=SESSION, prio=5, zh="", en="", preamble=None)
```

| Parameter | Description |
|---|---|
| `name` | technique name (also used for pheromone stats) |
| `requires` | required capability set |
| `provides` | provided capability set |
| `execute(ctx)` | body, returns True when the capability is gained |
| `feasible(ctx)` | deterministic feasibility predicate (decision-tree split) |
| `scope` | whether the provided capabilities are session or process scoped |
| `prio` | expert prior (lower goes first; pheromone can override it once enough evidence accumulates) |
| `zh` / `en` | human-readable descriptions for the log |
| `preamble` | input-stream prefix this technique lives in (multi-read programs) |

### `DecisionTree`

- `features(ctx)` -> dict: observed evidence (vuln kinds, mitigations, gadgets, capabilities held)
- `certified(ctx, edges)` -> list[Technique]: drops edges whose prerequisites are missing, that
  are infeasible, or whose capabilities are already fully held

### `Colony`

```python
from antpwn.graph import Colony

colony = Colony(edges, log, phero_path="antpwn_pheromone.json")
trail, ok = colony.solve(ctx, waves=4, ants_per_wave=2)
```

| Method | Description |
|---|---|
| `solve(ctx, waves=4, ants_per_wave=2)` | multiple waves; `(trail, True)` on success, `(None, False)` otherwise |
| `walk(ctx, budget=14)` | one ant; returns `(trail, ok, session_gained)` |
| `choose(ctx, cands)` | after certification, ranks by pheromone win-rate plus expert prior (10% exploration) |

`trail` is `[(Technique, ok), ...]`. Pheromone is stored as
"binary feature signature → edge → [wins, tries]" in `phero_path` (default
`antpwn_pheromone.json` in the current directory); delete the file to reset the experience.
There is no lock, so two concurrent runs can overwrite each other.

### Extending: add a technique

```python
from antpwn.graph import Technique, CAP_RIP, CAP_SHELL, SESSION, Colony
from antpwn.fsm import Logger

def execute(ctx):
    ...                     # build and send your own payload; True on success
    return True

my_edge = Technique(
    "my-chain", requires={CAP_RIP}, provides={CAP_SHELL},
    execute=execute,
    feasible=lambda c: "bof" in c.vuln_kinds,
    scope=SESSION, prio=8, zh="custom chain", en="custom chain")

edges = fsm.build_edges(ctx) + [my_edge]
colony = Colony(edges, Logger())
trail, ok = colony.solve(ctx)
```

---

## 11. `antpwn.exploits` — strategies and helpers

### Helpers

```python
from antpwn.exploits import cyclic, cyclic_find, find_libc, libc_offsets
from antpwn.exploits import scan_libc_ptr, p64, u64, SHELLCODE, SHELL_RESP

pattern = cyclic(200)             # cyclic pattern for offset discovery
idx = cyclic_find(pattern[72:80]) # decode the offset from a crashed value
path, libc = find_libc("./pwn")   # locate the target libc via ldd -> (path, ELF)
offs = libc_offsets(libc)         # {"puts":..., "system":..., "free":..., "/bin/sh":...}
res = scan_libc_ptr(leaked, offs["puts"])   # -> (leaked_ptr, libc_base) or None
p64(0x401234)                     # 8-byte little-endian pack
```

Constants: `SHELLCODE` (23-byte execve shellcode), `SHELL_MARKER` / `SHELL_RESP` (command and
echo marker used to verify a shell).

### `ExploitContext`

Shared state between the FSM and the strategies:

| Member | Description |
|---|---|
| `elf` / `scanner` / `gadgets` / `log` | upstream objects |
| `offset` | return-address offset used by the current strategy |
| `libc_path` / `libc` / `libc_off` | libc path, ELF and offset table |
| `fmt_k` | format-string argument index |
| `heap_leak` | heap leak information |
| `notes` | plain-words explanations `[(zh, en)]`, included in the report |
| `capabilities` | capabilities held (the DAG blackboard) |
| `live` | process-scoped state (tube, libc base, chunks, ...) |
| `offsets_map` | input-stream prefix → offset |

Helper judgements: `vuln_kinds`, `has_binsh`, `has_rop_gadgets`, `has_leak_function`,
`bof_finding()`, `bof_func_addr()`, `bof_is_line_input()`, `backdoor_addr()`. These are
**behaviour based** (does it really call `system("/bin/sh")`), not name based.

### Strategy classes

All strategies subclass `Strategy` and implement `feasible()` and `run()` (returns bool):

| Class | Technique |
|---|---|
| `Ret2Text` | jump to a backdoor function |
| `Ret2Libc` | leak puts → compute base → second return into system |
| `Ret2Syscall` | ROP chain for execve |
| `FmtGOT` | format string (with backdoor `%hn` / without, `%s` libc leak) |
| `Shellcode` | executable-stack injection |
| `SROP` | sigreturn frame |
| `StackPivot` | stack pivot |
| `HeapUAF` | tcache poisoning |
| `Ret2OneGadget` | leak libc, then jump to a one_gadget (when plain ret2libc does not apply) |
| `Ret2CsuOneGadget` | no `pop rdi`: `__libc_csu_init` leak + one_gadget |
| `Ret2Dlresolve` | fake Elf64 rela/sym/strtab resolved through plt0 (no libc needed) |
| `CanaryBrute` | byte-wise canary brute force on a remote fork server (`ANTPWN_BRUTE_MAX` caps probes) |
| `OffByNull` | experimental off-by-null stack overlap to the win function (off by default, `ANTPWN_OFFBYNULL=1`) |

`all_strategies()` returns built-ins plus registered plugins; `register_strategy(MyStrategy)`
adds a custom strategy to the FSM (`EXTRA_STRATEGIES` keeps plugin classes). Helpers:
`find_one_gadget_offsets(path)` (needs the optional `one_gadget`), `find_writable_bss(elf)`,
`csu_gadgets(elf)`. Standalone use:

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

## 12. `antpwn.fsm` — solver state machine

```python
from antpwn.fsm import FSM, State, Logger

fsm = FSM(path, log=None, lang="zh", remote=None, keep_shell=False)
ok = fsm.run()
```

| Parameter | Description |
|---|---|
| `path` | local binary (used for static analysis even for remote targets) |
| `remote` | `(host, port)`: exploit traffic goes over TCP, analysis stays local |
| `keep_shell` | keep the shell open on success (for `fsm.interactive()`) |
| `use_pheromone` | load/save `antpwn_pheromone.json` (CLI `--no-pheromone`) |
| `libc_path` | explicit libc (CLI `--libc`); `ldd` is used when omitted |

### Run

`run()` goes RECON → DECOMPILE → SCAN → STRATEGY (capability DAG + colony) → on failure falls
back to the legacy linear strategy list → on success VERIFY. Returns `True` when a shell was
obtained.

### Attributes

| Attribute | Description |
|---|---|
| `state` | current state (`State.*`) |
| `trace` | `[(cur, event, next), ...]` transition record |
| `report_data` | report data, see below |
| `log` | `Logger` (`records` keeps every log line) |
| `elf` / `scanner` / `ctx` | analysis objects and the shared context |

`report_data` keys:

```
path, mitigations{pie,nx,canary,relro,execstack,arch}, functions[],
findings[], strategies[], offset, aco[], notes[], result, steps[],
flag, shell_output, remote, pheromone{edge: {wins, tries}}, pheromone_enabled
```

`result` values: `pwned:dag` / `pwned:<strategy>` / `failed` / `not_elf`.
`flag` is the flag captured from the shell (None if not found); `shell_output` is the raw
output read while hunting; `remote` is `host:port` or None.

### Shell interaction and flag capture

| Method | Description |
|---|---|
| `_grab_flag()` | run `id`/`pwd`/`ls -la`/`cat flag*` in the live shell, return the first flag match (`FLAG_RE`) |
| `_announce_flag()` | print the flag, or the first lines of shell output; close the shell unless `keep_shell` |
| `interactive()` | hand over the shell: stdin lines go to the target, output is echoed; `exit`/`quit`/EOF leaves (readline editing/history) |

`--remote` + `-i` together mean "exploit the remote and stay in the shell":

```python
fsm = FSM("./pwn200", remote=("10.0.0.1", 1337), keep_shell=True)
if fsm.run():
    fsm.interactive()
```

### Offset inference

| Method | Description |
|---|---|
| `dt_find_offset(preamble=b"")` | crash forensics: decode the cyclic pattern from one crash, then verify with a marker; None when undecidable |
| `find_offset(strategy)` | ACO fallback (includes a crashability pre-check) |
| `crash_score(off, marker, preamble=b"")` | RIP control degree, 0.0 to 1.0 |
| `static_buf_estimate()` | estimate the buffer size from `sub rsp,N` / `[rbp-N]` |
| `build_edges(ctx)` | build the built-in capability DAG edge list (for custom extensions) |

### State constants

`State.RECON / DECOMPILE / SCAN / STRATEGY / OFFSET / BUILD / TEST / VERIFY / DONE / FAILED`

### Logging

```python
from antpwn.fsm import Logger

log = Logger(verbose=False)      # collect without printing
fsm = FSM(path, log=log)
fsm.run()
print("\n".join(log.records))
```

---

## 13. `antpwn.report` — HTML report

```python
from antpwn.report import save_report

path = save_report(fsm, "out.html")     # returns the written path
```

Report content: mitigations, function table, findings with scores, strategy routes, ACO
records, plain-words explanations and the result. Language follows the FSM language setting.

---

## 14. `antpwn.i18n` — language control

```python
from antpwn import i18n

i18n.set_lang("en")        # "zh" / "en"; None leaves it unchanged
print(i18n.t("recon"))     # lookup; unknown keys are returned as-is
```

Language is module-level global state; it affects `Finding.text`, logs and reports.

---

## 15. Recipes

### 15.1 Batch-scan a directory (static only)

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

### 15.2 Use mitigation facts in your own decision logic

```python
elf = ELF(target)
has_pop_rdi = "pop rdi" in GadgetFinder(elf).find_all()
risky = (elf.is_pie or elf.canary) and not elf.has_nx
```

### 15.3 Drive the process yourself, borrow only the crash analysis

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

### 15.4 Search other parameters with ACO

```python
from antpwn.aco import AntColony

# example: format-string argument index search
dims = [list(range(1, 41))]
colony = AntColony(dims, fitness=lambda v: 1.0 if probe(v[0]) else 0.0,
                   ants=8, iters=6, seed=1)
best, score = colony.run()
```

### 15.5 Run a single strategy instead of the whole FSM

See `ExploitContext` + `Ret2Text(ctx).run()` in section 11. Useful when you already know the
route and only want AntPwn's probing and sending logic.

---

## 16. Boundaries and pitfalls

- **Platform**: Linux x86-64 only. `debugger` loads `libc.so.6` at import time, so even
  `import antpwn` fails on Windows/macOS.
- **32-bit**: `ELF` raises `ELFError`; the whole analysis is designed around x86-64.
- **Global state**: `i18n.LANG` is module-level, so concurrent tasks in one process affect each
  other's language.
- **Pheromone file**: written to `antpwn_pheromone.json` in the current working directory by
  default; no locking, concurrent runs overwrite each other. For tests/CI pass an explicit
  `phero_path` or delete the file first to keep results reproducible.
- **`Process` is quiet by default**: with `quiet=True` the child's stdout/stderr go to
  `/dev/null`; use `Tube` to read output, `Process` to inspect crash sites.
- **`find_libc` relies on `ldd`**: remote targets require the same libc locally; environments
  without `ldd` will fail.
- **The scan is heuristic**: `score` is a ranking hint, not a conclusion; the dynamic
  verification in `FSM.run()` is the final word.
- **API stability**: within v1.x the documented public members are stable; underscore-prefixed
  methods and attributes are internal and may change between releases.

---

## 17. `antpwn.color` — terminal colour styling

```python
from antpwn import color

color.enabled()                       # whether styling is active (cached decision)
color.style("text", "bold", "red")    # generic ANSI wrapper
color.strip(s)                        # remove ANSI escapes (for files/assertions)
```

Semantic helpers (already keyed to finding kind, severity and FSM state):

| Helper | Purpose |
|---|---|
| `head` / `section` / `info` / `dim` | heading, section, info, de-emphasis |
| `ok` / `good` / `warn` / `err` | success, strong success, warning, error |
| `value_yes` / `value_no` | mitigation ON (warm) / OFF (cool) |
| `kind(name)` / `score(n)` | finding kind / severity score |
| `state(name)` / `event(ok, text)` | state-machine tag / transition |

Rules:

- ANSI is emitted only when stdout is a TTY; pipes, redirections and `capture_output` get plain
  text, so string matching in `tests/run_all.py` is unaffected;
- `ANTPWN_COLOR=1/0` forces it on/off; `NO_COLOR` / `CLICOLOR=0` disables it;
- on Windows console VT processing is enabled automatically, falling back to plain text on failure;
- the CLI exposes it as `--color auto|always|never` (default `auto`).

---

## 18. `antpwn.repl` — interactive browser (r2-style)

```python
from antpwn.elf import ELF
from antpwn.repl import Repl

Repl(ELF("./pwn200")).run()
```

CLI: `python3 antpwn.py view <binary>` (alias `repl`).

| Command | Description |
|---|---|
| `info` / `i` | mitigations, entry, counts of functions/sections/strings |
| `ls [pat]` | list functions (filter by name, 200 lines by default) |
| `disas [func\|0xaddr] [n]` | disassemble, `n` is a byte count (symbol size or 0x40 by default) |
| `pseudo [func\|0xaddr]` | pseudo-code (needs a function symbol; an address resolves to its function) |
| `calls [func]` | callees of a function |
| `vuln [kind\|func]` / `bugs` / `check` | scan findings, list by severity, filterable; builds highlight markers |
| `strings [minlen]` | list strings |
| `find <text>` / `/` | search function names and strings |
| `xrefs [func]` / `callers` | callers + callees (call graph built lazily) |
| `gadget [name\|pattern]` | gadget search, free-form patterns like `gadget "pop rdi; ret"` |
| `export <file.json\|file.html>` | export mitigations/functions/findings for sharing |
| `gadgets` / `rop` | ROP gadget summary |
| `plt` / `imports` | PLT imports |
| `sec` / `sections` | sections and segments |
| `x <addr> [n]` | hex view |
| `quit` / `q` / `exit` | leave |

- `Repl` is read-only static browsing; it does not execute the target and needs no
  pwntools/rizin. Commands are backed by `ELF` / `Disasm` / `Decompiler` / `GadgetFinder`.
- Piped input is supported for scripting and self-tests:
  `printf 'info\nls\ndisas vuln\nquit\n' | python3 antpwn.py view ./pwn`.
- **Vulnerability highlighting**: `vuln` runs `Scanner` once and records findings in
  `Repl.vuln_ranges`; `disas` then draws a `|` rail over vulnerable functions and puts a
  strong `!` marker on the dangerous call line with `; kind score  <= evidence`; `pseudo`
  shows `// [VULN]` in the function header and colours dangerous calls; `ls` prefixes
  vulnerable functions with `!`.
- **readline**: interactive input goes through `antpwn.histedit.read_line()` (`input()`
  semantics), so on Linux/macOS you get arrow-key editing, up/down history and Tab
  completion (commands for the first word, symbol names for `disas`/`pseudo`/`calls`).
  On Windows, where CPython has no `readline`, it degrades to plain input.

### `antpwn.histedit` — optional line editing

```python
from antpwn import histedit

histedit.available()                    # is readline importable
histedit.setup(completer=None, histfile=None)   # enable, returns success
histedit.read_line("prompt> ")          # read one line ("" on EOF)
histedit.save()                         # persist history
```

History defaults to `~/.antpwn_history`; `ANTPWN_HISTORY=/path` overrides it and
`ANTPWN_NO_HISTORY=1` disables persistence. Both `view` and the `-i` shell use it.

---

## 19. Packaging, tests and CI

- `pyproject.toml`: `pip install .` provides the `antpwn` console command
  (`antpwn = "antpwn.cli:main"`); its version must match `antpwn.__version__` (CI checks this).
- Unit tests: `python3 -m unittest discover -s tests -v` (stdlib only, no pytest). They cover ELF
  parsing, stripped-function discovery, disassembly, pseudo-code, scanning, dataflow, colour,
  plugin registration, `view` export and packaging consistency.
- Full regression: `python3 tests/run_all.py` (spawns challenge processes; run on demand locally,
  not in CI).
- CI: `.github/workflows/test.yml` runs version checks, `py_compile`, analyze/view/pwn smoke,
  unit tests and a wheel build; `.github/workflows/release.yml` handles tag-driven releases.
- Plugin entry points: `from antpwn import register_strategy, register_technique`.

---

## 20. `antpwn.gdbplugin` — the gdb plugin

Use the same analysis engine from inside gdb (no third-party packages; gdb's own
Python interpreter is enough):

```text
(gdb) source /path/to/AntPwn/antpwn-gdb.py
(gdb) antpwn help
```

or in `~/.gdbinit`:

```python
python import sys; sys.path.insert(0, "/path/to/AntPwn"); import antpwn.gdbplugin; antpwn.gdbplugin.register()
```

Commands:

| command | purpose |
|---|---|
| `antpwn recon` / `info` | mitigations, entry, function/string counts |
| `antpwn vuln [kind\|func]` | scan and highlight findings (same source as `view vuln`) |
| `antpwn disas [func\|addr] [n]` | disassembly with `\|`/`!` rails on vulnerable lines and `=>` at `$pc` |
| `antpwn pseudo [func\|addr]` | pseudo-code |
| `antpwn xrefs [func]` | callers + callees (recursive scan, fewer false hits) |
| `antpwn offset [gen [n]]` | decode the cyclic offset from the current crash; `gen` writes a pattern file |
| `antpwn trace on\|off\|show` | breakpoints on dangerous PLT calls, logging args + backtrace, auto-continue |
| `antpwn plan` | rank strategies from capabilities known in this session (offset, libc base) |
| `antpwn prompt on\|off` | toggle the dedicated prompt (on by default; off restores gdb's prompt) |
| `antpwn lang zh\|en` | switch language |
| other `view` commands | `ls` / `strings` / `find` / `gadget` / `export` / `x` ... work as-is |

Design: read-only commands reuse `Repl`/`Scanner`, so gdb findings match the CLI;
`offset` reads crash registers/memory through gdb instead of starting a second
ptrace debugger (two debuggers cannot own the same process); `trace` subclasses
`gdb.Breakpoint` and returns `False` from `stop()` to auto-continue; `plan` combines
static feasibility of `all_strategies()` with session capabilities and never
executes an exploit.

Limits: remote targets are still better served by the CLI (`pwn --remote`); the
plugin does not run exploits or large brute-force loops; gdb must be built with
Python support (the norm on mainstream distributions).
