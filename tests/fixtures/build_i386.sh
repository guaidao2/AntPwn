#!/bin/sh
# Build the 32-bit ELF fixtures.
# - asm fixtures: binutils only (as --32 + ld -m elf_i386), no gcc-multilib needed
# - i386_ret2libc: needs gcc -m32 with 32-bit libc headers/libs (optional)
set -eu
cd "$(dirname "$0")"
for name in i386_bof i386_loop i386_syscall i386_shellcode; do
    extra=""
    if [ "$name" = "i386_shellcode" ]; then
        extra="-z execstack"
    fi
    as --32 "$name.s" -o "/tmp/$name.o"
    ld -m elf_i386 $extra "/tmp/$name.o" -o "$name"
    rm -f "/tmp/$name.o"
    echo "built $name"
done
if gcc -m32 -fno-stack-protector -no-pie -o i386_ret2libc i386_ret2libc.c 2>/dev/null; then
    echo "built i386_ret2libc"
else
    echo "skip i386_ret2libc (gcc -m32 / 32-bit libc not available)"
fi
if gcc -m32 -fno-stack-protector -no-pie -o i386_fmt i386_fmt.c 2>/dev/null; then
    echo "built i386_fmt"
else
    echo "skip i386_fmt (gcc -m32 / 32-bit libc not available)"
fi
if gcc -m32 -no-pie -z execstack -fno-stack-protector -o i386_shellcode_leak i386_shellcode_leak.s 2>/dev/null; then
    echo "built i386_shellcode_leak"
else
    echo "skip i386_shellcode_leak (gcc -m32 / 32-bit libc not available)"
fi
if gcc -m32 -no-pie -fno-stack-protector -o i386_write_leak i386_write_leak.s 2>/dev/null; then
    echo "built i386_write_leak"
else
    echo "skip i386_write_leak (gcc -m32 / 32-bit libc not available)"
fi
if gcc -m32 -fno-stack-protector -no-pie -o i386_fmt_libc i386_fmt_libc.c 2>/dev/null; then
    echo "built i386_fmt_libc"
else
    echo "skip i386_fmt_libc (gcc -m32 / 32-bit libc not available)"
fi
