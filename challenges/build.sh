#!/bin/bash
# Build all challenges 构建全部题目
set -e
cd "$(dirname "$0")"
SRC=src
mkdir -p bin
COMMON="-fno-stack-protector -no-pie -O0 -g"

# 1. baby_bof: ret2text
gcc $COMMON -Wno-implicit-function-declaration $SRC/baby_bof.c -o bin/baby_bof

# 2. ret2libc: NX + partial RELRO, needs gadget farm
gcc $COMMON $SRC/ret2libc.c $SRC/gadgets.S -o bin/ret2libc

# 3. r2syscall: ROP to execve
gcc $COMMON $SRC/r2syscall.c $SRC/gadgets.S -o bin/r2syscall

# 4. fmt_got: format string
gcc $COMMON $SRC/fmt_got.c -Wno-format-security -o bin/fmt_got

# 5. shellcode64: executable stack
gcc $COMMON -z execstack $SRC/shellcode64.c $SRC/gadgets.S -o bin/shellcode64

# 6. heap_uaf: heap UAF / tcache (partial RELRO for hook overwrite)
gcc $COMMON $SRC/heap_uaf.c -o bin/heap_uaf

# 7. srop: sigreturn ROP
gcc $COMMON $SRC/srop.c $SRC/gadgets.S -o bin/srop

# 8. pivot: stack pivot to bss
gcc $COMMON $SRC/pivot.c $SRC/gadgets.S -o bin/pivot

chmod +x bin/*
echo "== build done =="
ls -l bin/
