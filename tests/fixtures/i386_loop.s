# tests/fixtures/i386_loop.s — 32-bit fixture with a loop and an if/else,
# built with: as --32 + ld -m elf_i386
.intel_syntax noprefix
.section .text
.globl _start
.type _start, @function
_start:
    call compute
    mov eax, 1
    xor ebx, ebx
    int 0x80
.size _start, .-_start

.globl compute
.type compute, @function
compute:
    push ebp
    mov ebp, esp
    sub esp, 0x10
    mov dword ptr [ebp-4], 0        # i = 0
    mov dword ptr [ebp-8], 0        # sum = 0
.Lloop:
    cmp dword ptr [ebp-4], 10
    jge .Ldone
    mov eax, dword ptr [ebp-4]
    add dword ptr [ebp-8], eax
    add dword ptr [ebp-4], 1
    jmp .Lloop
.Ldone:
    cmp dword ptr [ebp-8], 45
    jne .Lno
    mov eax, 1
    leave
    ret
.Lno:
    xor eax, eax
    leave
    ret
.size compute, .-compute
