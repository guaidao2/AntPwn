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
