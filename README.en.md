# AntPwn — Pwn Analysis Assistant (Analysis · Planning · Auto Verification)

[中文](README.md) | **English**

> by guaidao2 · coolmoon

**author: guaidao2** · version 1.5.3 · bilingual (zh / en)

> Native static analysis · pseudo-code recovery · vulnerability scanning · ptrace debugging ·
> capability-DAG planning · state-machine driven

**Zero third-party dependencies**: no pwntools / gdb / capstone / ropper / angr. Everything is
implemented in plain Python (own ELF64 parser, x86-64 disassembler, ptrace debugger, libc
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
| Static analysis | Native ELF64 parsing: PIE / NX / Canary / RELRO / ExecStack detection, symbols, PLT/GOT, relocations |
| Pseudo-code | Own disassembler plus argument folding, emits C-like pseudo-code: `read(0, v0, 0x200)`, `system("/bin/sh")` |
| Vulnerability scan | Rule engine plus pattern matching: stack overflow / format string / UAF / backdoor functions / dangerous strings, severity-scored |
| Dynamic debugging | ctypes-ptrace debugger: software breakpoints, single step, register and memory access, crash-site analysis |
| Planning | Capability DAG + decision tree + ant colony: capabilities are scoped session/process, capabilities left by failed ants are reused, offsets are inferred by crash forensics, pheromone persists per binary signature |
| State machine | RECON → DECOMPILE → SCAN → STRATEGY → OFFSET → BUILD → TEST → VERIFY, every step explained in plain words |
| Auto verification | 8 userland strategies, selected by behaviour rather than function names; a successful run gives an interactive shell, used to verify the judgement, not to do your job for you |
| Failure diagnosis | When a strategy is not feasible it says why: missing gadget, no leak channel, where PIE or Canary blocks the chain, and what to try next |
| Flag capture | After getting a shell it runs `id` / `pwd` / `ls` / `cat flag*` etc. and prints the first `flag{...}`-shaped match |
| Remote targets | `--remote HOST:PORT`: the local binary is used for analysis, the exploit traffic goes over TCP, same DAG/strategies |
| Interactive shell | `-i`: after success the shell is handed to you; type commands line by line, see output immediately; readline editing/history/completion |
| Interactive browser | `view <binary>`: r2-style session with `info` / `ls` / `disas` / `pseudo` / `calls` / `x` / `vuln` / `xrefs` / `gadget` / `export`; findings are highlighted, readline enabled |
| Stripped support | without symbols, functions are recovered from the entry point, recursive call targets and prologue patterns, so `analyze`/`view` still work |
| Dataflow scan | correlates `read`/`scanf` lengths with stack buffer sizes: exact overflow bytes, off-by-one detection, and no false positive for width-limited `scanf("%63s")` |
| New strategies | `one_gadget`, `ret2csu` (with one_gadget), `ret2dlresolve`, byte-wise canary brute force (remote fork servers) |
| Plugin API | `register_strategy()` / `register_technique()` add strategies and capability-DAG edges without touching the core |
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
4. **Format string** — `%p` spray locates the argument index dynamically; with a backdoor, `%hn` overwrites the GOT, **without one, `%s` leaks libc → printf@GOT→system** (generic route)
5. **shellcode** — ExecStack + `jmp rsp`
6. **SROP** — forged sigreturn frame
7. **Stack pivot** — small overflow + `leave;ret` into bss
8. **Heap (UAF)** — two UAF reads recover exact safe-linking chunk addresses → tcache poisoning into a function-pointer array → forge a slot → leak libc → `free@GOT = system`

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
proc.send(b"AAAA\n"); proc.cont()   # ptrace: registers/memory/breakpoints
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
│   ├── elf.py         #   ELF64 parser
│   ├── disasm.py      #   x86-64 disassembler (cross-checked against objdump)
│   ├── decompiler.py  #   pseudo-code recovery
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
├── pyproject.toml     # pip install + console script (antpwn after pip install .)
├── .github/workflows/ # test.yml (CI smoke + unit tests), release.yml (tag release)
├── docs/API.md        # full API reference (中文), API.en.md (English)
├── README.en.md       # English README (this file)
└── tests/             # test_core.py (stdlib unittest) + run_all.py (full regression)
```

## Limitations

- ELF64 / x86-64 only (the development environment has no 32-bit libs); 32-bit and statically
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

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 guaidao2 & coolmoon.

---

*AntPwn — analysis assistant for CTF pwn: explainable, embeddable, dependency-free. by guaidao2*
