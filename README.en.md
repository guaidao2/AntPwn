# AntPwn — Pwn Analysis Assistant (Analysis · Planning · Auto Verification)

[中文](README.md) | **English**

> by guaidao2 · coolmoon

**author: guaidao2** · version 1.7.3 · bilingual (zh / en)

> Native static analysis · pseudo-code recovery · vulnerability scanning · ptrace debugging ·
> capability-DAG planning · state-machine driven

**Zero third-party dependencies**: no pwntools / gdb / capstone / ropper / angr. Everything is
implemented in plain Python (own ELF32/ELF64 parser, x86-32/64 disassembler, ptrace debugger, libc
offset extraction).

---

## Positioning: it is an assistant, not a payload vending machine

AntPwn is built around **assisted analysis and decision support**: it opens the binary, reads
its mitigations, ranks the bugs by severity, proposes an explainable exploitation route, and
then **runs that route once to verify it**. It does not hand you an exploit script or payload
text, and it does not promise "drop it in, get a flag" — it gives you the judgement, the
evidence and the verification result, so you can understand it, take over, and reproduce it.

In this picture, auto-exploitation (`pwn`) is a **verification step**: the tool picks a path
through its capability DAG according to its decision tree and actually spawns the process to
try it. Success means the judgement holds; failure means it explains why. What you see is not
a pile of magic bytes, but a running account of what it thinks, on what evidence, and why it
went that way.

The tiny footprint is deliberate: pure standard library, so it runs in offline, no-pip CTF
containers and can be imported as a library into your own toolchain.

## Features

| Module | Description |
|---|---|
| Static analysis | Native ELF32/ELF64 parsing: PIE / NX / Canary / RELRO / ExecStack detection, symbols, PLT/GOT, relocations |
| Pseudo-code | own disassembler → P-code-like IR → CFG/dominators/natural loops → dataflow simplification → structured recovery (if/else, while, do-while), emitted as syntax-highlighted C-like pseudo-code: `while (1) { menu(); if (fgets@plt(v0, 0x20, stdin) == 0) break; ... }` |
| Vulnerability scan | Rule engine plus pattern matching: stack overflow / format string / UAF / backdoor functions / heap overflows (including off-by-one) / dangerous strings, severity-scored; ranked by call-graph reachability from main (user code first) with duplicate findings collapsed so large binaries stay readable |
| Dynamic debugging | ctypes-ptrace debugger: software breakpoints, single step, register and memory access, crash-site analysis |
| Planning | Capability DAG + decision tree + ant colony: capabilities are scoped session/process, capabilities left by failed ants are reused, offsets are inferred by crash forensics, pheromone persists per binary signature |
| State machine | RECON → DECOMPILE → SCAN → STRATEGY → OFFSET → BUILD → TEST → VERIFY, every step explained in plain words |
| Auto verification | multiple userland strategies (8 core + conditional/experimental), selected by behaviour rather than function names; a successful run gives an interactive shell, used to verify the judgement, not to do your job for you |
| Failure diagnosis | When a strategy is not feasible it says why: missing gadget, no leak channel, where PIE or Canary blocks the chain, and what to try next |
| Flag capture | After getting a shell it runs `id` / `pwd` / `ls` / `cat flag*` etc. and prints the first `flag{...}`-shaped match |
| Remote targets | `--remote HOST:PORT`: the local binary is used for analysis, the exploit traffic goes over TCP, same DAG/strategies |
| Interactive shell | `-i`: after success the shell is handed to you; type commands line by line, see output immediately; readline editing/history/completion |
| Interactive browser | `view <binary>`: r2-style session with `info` / `ls` / `disas` / `pseudo` / `calls` / `x` / `vuln` / `xrefs` / `gadget` / `export`; findings are highlighted, readline enabled |
| Stripped support | without symbols, functions are recovered from the entry point, recursive call targets and prologue patterns, so `analyze`/`view` still work |
| Dataflow scan | correlates `read`/`scanf` lengths with stack buffer sizes: exact overflow bytes, off-by-one detection, and no false positive for width-limited `scanf("%63s")` |
| New strategies | `one_gadget`, `ret2csu` (with one_gadget), `ret2dlresolve`, byte-wise canary brute force (remote fork servers) |
| Plugin API | `register_strategy()` / `register_technique()` add strategies and capability-DAG edges without touching the core |
| gdb plugin | `source antpwn-gdb.py` (or `antpwn-gdb ./vuln` launches gdb with the plugin; `antpwn-gdb --write` appends the .gdbinit line). Commands: `where`/`recon`/`vuln --bp`/`disas` (defaults to `$pc`)/`pseudo`/`x $rsp`/`leak`/`maps`/`offset [gen\|0x..]`/`trace on [funcs] [--stop --max=N --dump]`/`plan` (paste-ready next steps)/`report`/`export`/`reset`; dedicated prompt, tab completion, zh/en, coexists with gef/pwndbg |
| Structured / reproducible | `pwn --json` (full result incl. trace and pheromone), `--no-pheromone`, `--libc PATH`, `--retries N`; `view export` writes html/json |
| Reporting / i18n | `--lang zh / en`; `--report out.html` writes the conclusions and decision record |
| Terminal colour | ANSI styling on a TTY; `--color always / never` or `NO_COLOR` / `ANTPWN_COLOR` to override; pipes and logs degrade to plain text |
| Embeddable | `antpwn` is a pure-stdlib package; the CLI is a thin shell, analysis/debugging/state machine can be used directly as a library |

## When it fits

- You have an unknown binary and want the mitigations, the bugs and one explainable route fast;
- You want to follow the log and understand why one chain works and another does not, instead
  of just receiving a script;
- You want to embed ELF analysis, pseudo-code, ptrace debugging or auto verification into your
  own tool or platform;
- Your environment is restricted (offline, no package installs, only `python3` in the container)
  but you still need a full analysis chain.

If what you want is batch generation of exploit scripts, that is a different product; AntPwn
chooses to explain the process and leave the last mile to the human.

## Supported userland strategies

1. **ret2text** — detect a backdoor function (behaviour: `system("/bin/sh")`, or a suspicious symbol name)
2. **ret2libc** — leak `puts@GOT` → compute libc base → return into the vulnerable function again → `system("/bin/sh")`
3. **ret2syscall** — ROP chain that sets up registers → `execve("/bin/sh",0,0)`
4. **Format string** — bits-aware `%p` spray for the argument index, automatic detection of interaction rounds and of any printf call after our input; `%hn` GOT overwrite with a backdoor, `%s` libc leak + printf→system without one, and an explicit diagnosis for single-round targets with no trigger point — `%p` spray locates the argument index dynamically; with a backdoor, `%hn` overwrites the GOT, **without one, `%s` leaks libc → printf@GOT→system** (generic route)
5. **shellcode** — ExecStack + stack-jump gadgets such as `jmp rsp`/`call rsp`; when no gadget exists, reuse a buffer address printed by the same process (validated, stack-like first), for both 64- and 32-bit targets
6. **SROP** — forged sigreturn frame
7. **Stack pivot** — small overflow + `leave;ret` into bss
8. **Heap (UAF)** — two UAF reads recover exact safe-linking chunk addresses → tcache poisoning into a function-pointer array → forge a slot → leak libc → `free@GOT = system`
9. **leaked-win / PIE** — derive the PIE base from any printed code pointer by matching known function offsets, then ret2win (not limited to printing win); with no leak at all, try a partial overwrite of the saved return address's low 1-2 bytes (enumerating the 16 possible page carries of the base)
10. **generic heap menu (heap_menu)** — option numbers come from the `cmp/je` dispatch chain and are mapped to handlers, which are classified by their own calls (malloc/free/write/read) into add/del/show/edit, so arbitrary labels or even stripped binaries work; leak path by capability (printed address / raw show bytes / double-free safe-linking iteration; under PIE a printed code pointer is used to recover the base first) / raw show bytes / double-free safe-linking iteration) and GOT target from got_map, with no challenge-specific hard-coding

- Argument loading in stack strategies goes through `pick_arg_gadget` / `chain_set`: compound gadgets are used with automatic padding when the canonical single-pop gadget is missing (shared by ret2libc / ret2syscall / ret2dlresolve)

## Quick Start

```bash
# Analysis only (mitigations + vulnerability scan + pseudo-code), no target process spawned
python3 antpwn.py analyze ./challenges/bin/baby_bof --pseudo

# Pseudo-code of one function
python3 antpwn.py analyze ./baby_bof --pseudo --func vuln

# Let the tool walk its own route and verify it (an interactive shell on success)
python3 antpwn.py pwn ./challenges/bin/ret2libc

# Verification + HTML report + English output
python3 antpwn.py pwn ./pwn200 --report out.html --lang en

# Attack a remote service: local binary for analysis, exploit traffic over TCP
python3 antpwn.py pwn ./challenges/bin/ret2libc --remote 10.0.0.1:1337

# Take over the shell after success (type commands, read output)
python3 antpwn.py pwn ./challenges/bin/baby_bof -i

# r2-style interactive browser for disassembly and pseudo-code
python3 antpwn.py view ./challenges/bin/baby_bof

# remote + explicit libc + retries
python3 antpwn.py pwn ./pwn --remote 10.0.0.1:1337 --libc ./libc-2.31.so --retries 3

# machine-readable result / reproducible run (no pheromone I/O)
python3 antpwn.py pwn ./pwn --json out.json --no-pheromone

# after pip install . the antpwn command is available
pip install .

# drive the analysis engine from gdb (just source the loader)
gdb -q ./challenges/bin/baby_bof
(gdb) source /root/AntPwn/antpwn-gdb.py
(gdb) antpwn where            # context around $pc, stack, registers, backtrace
(gdb) antpwn vuln --bp        # findings + paste-ready breakpoints
(gdb) antpwn disas            # defaults to the current $pc
(gdb) antpwn trace on gets --stop --dump
(gdb) run < antpwn_pattern.bin             # generated by antpwn offset gen
(gdb) antpwn offset           # decode offset, writes $antpwn_offset + pheromone
(gdb) antpwn plan             # routes + the next command to type
(gdb) antpwn report           # HTML session report
```

All key parameters (overflow offset, format-string argument index, heap chunk addresses) are
probed dynamically; nothing relies on particular function names or challenge hints. The
reasoning and the failure explanation are both written to the step log and the report.

## Library API

`antpwn` is a pure-stdlib package; the CLI is only a thin shell. Analysis, disassembly,
debugging, planning and reporting can all be called directly.

```python
from antpwn import ELF, Decompiler, Scanner, GadgetFinder, Process, FSM, Tube

elf  = ELF("./vuln")                 # parse: mitigations/gadgets/GOT/symbols
dc   = Decompiler(elf)               # pseudo-code recovery
pf   = dc.function(elf.sym("main"))  # -> PseudoFunc (lines/calls/string_refs)
scan = Scanner(elf); scan.scan()     # vulnerability scan (bof/fmt/heap/backdoor)
gf   = GadgetFinder(elf)
rdi  = gf.first("pop rdi")           # address of the first pop rdi, None if absent
proc = Process("./vuln"); proc.start()
proc.send(b"AAAA
"); proc.cont()   # ptrace: registers/memory/breakpoints
regs = proc.getregs(); mem = proc.read_mem(regs.rsp, 0x40)

fsm = FSM("./vuln")                  # decision tree x ant colony x capability DAG
ok  = fsm.run()                      # -> True, report_data holds the full record
```

Full reference (modules, parameters, data structures, extension examples, pitfalls):
**[docs/API.en.md](docs/API.en.md)** (English) / **[docs/API.md](docs/API.md)** (中文).

Wiring these objects into your own script, platform or CTF tooling is the other way to use
AntPwn as an assistant.

## Self-test / Verification

```bash
bash challenges/build.sh      # rebuild the 8 built-in challenges
python3 tests/run_all.py      # 11/11 solved (8 challenges + 2 blind + 1 optimized)
                              # plus 2 unsolvable-by-design ones (t2_canary / t3_pie)
                              # to verify "graceful failure + diagnosis"
```

**Blind tests demonstrate generality** (`challenges/blind/`, different function names, hints
and offsets from the development set):
- `mystery1`: no backdoor, no /bin/sh, unfamiliar symbol names → takes the generic ret2libc leak chain (pass)
- `mystery2`: format string without a backdoor → takes the generic fmt→libc route (pass)

Analysing `/bin/ls` (stripped + PIE + Full RELRO) does not crash and reports protections and
findings normally. The whole self-test needs no third-party Python package.

## Layout

```
AntPwn/
├── antpwn/            # core package (pure Python, zero dependencies)
│   ├── elf.py         #   ELF32/ELF64 parser
│   ├── disasm.py      #   x86-32/64 disassembler (cross-checked against objdump)
│   ├── ir.py          #   P-code-like IR / CFG / dominators / loops / stack vars
│   ├── decompiler.py  #   structured decompiler (IR -> if/else/while -> coloured C)
│   ├── scanner.py     #   vulnerability scan rule engine
│   ├── gadgets.py     #   ROP gadget search
│   ├── debugger.py    #   ptrace debugger
│   ├── procio.py      #   process interaction tube
│   ├── aco.py         #   ant colony optimisation
│   ├── graph.py       #   capability DAG + decision tree + pheromone
│   ├── exploits.py    #   8 exploitation strategies
│   ├── fsm.py         #   solver state machine
│   ├── i18n.py        #   bilingual strings
│   ├── color.py       #   terminal colour styling (TTY only)
│   ├── repl.py        #   interactive disasm / pseudo-code browser (view)
│   ├── histedit.py    #   readline editing / history / completion (optional)
│   ├── report.py      #   HTML report
│   └── cli.py         #   command line entry
├── challenges/        # 8 original challenges (with source) + 3 advanced + 2 blind
├── antpwn-gdb.py      # gdb plugin loader (source this file inside gdb)
├── antpwn/gdb_loader.py # `antpwn-gdb` command: launch gdb with the plugin, or print/append the .gdbinit snippet
├── pyproject.toml     # pip install + console script (antpwn after pip install .)
├── .github/workflows/ # test.yml (CI smoke + unit tests), release.yml (tag release)
├── docs/API.md        # full API reference (中文), API.en.md (English)
├── README.en.md       # English README (this file)
└── tests/             # test_core.py + gdb_smoke.sh (real gdb inferior) + run_all.py
```

## Limitations

- Static analysis and decompilation cover ELF64 / x86-64 and ELF32 / i386; 32-bit exploitation covers ret2text, ret2syscall (int 0x80), shellcode and the cdecl ret2libc two-stage chain (puts or write leaks); fmt now supports both 32- and 64-bit (automatically avoiding newline bytes that would break line input); heap / SROP / pivot remain 64-bit only
  linked targets are not covered yet
- `antpwn_pheromone.json` is a learning artefact (edge statistics keyed by binary features);
  delete it to reset the experience
- PIE with no leak channel, Full RELRO with no fmt/heap bug, Canary with no leak and similar
  "unsolvable or advanced-only" cases are reported as failures with a diagnosis instead of
  inventing a path
- **No standalone exploit script or payload text is generated**: payloads are built and sent
  in-process; to reproduce, write your own script from the strategy and parameters in the report
- Remote targets need a matching local libc (located via `ldd`, or pass `--libc`); remote
  interaction is not built in yet (reuse `antpwn.procio.Tube`)
- Canary brute force only applies to remote fork servers where wrong/right guesses are
  distinguishable by connection behaviour; single-shot processes cannot be brute-forced
- off-by-one / off-by-null is detected and scored by default; an experimental stack-overlap
  exploit ships too (`ANTPWN_OFFBYNULL=1`), but success depends on the stack address low byte
  landing inside the buffer, so it is not generic
- `ret2csu` finishes with one_gadget on binaries without a `pop rdi` gadget (requires the
  optional `one_gadget` tool installed locally)
- the gdb plugin does not run exploits or brute-force loops; remote targets are best served
  by the CLI, and static/musl targets are reported as "no libc mapping" by `plan`
- Time budget: `ANTPWN_MAX_SECONDS` (default 900s, 0 disables) caps the total time of one automatic run; PIE partial-overwrite brute force and heap-menu multi-path attempts stop early with a diagnosis when it expires

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 guaidao2 & coolmoon.

---

*AntPwn — analysis assistant for CTF pwn: explainable, embeddable, dependency-free. by guaidao2*
