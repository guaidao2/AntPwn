# tests/fixtures/i386_bof.s — 32-bit (i386) fixture, built with: as --32 + ld -m elf_i386
.intel_syntax noprefix
.section .text
.globl _start
.type _start, @function
_start:
    call vuln
    mov eax, 1
    xor ebx, ebx
    int 0x80
.size _start, .-_start

.globl vuln
.type vuln, @function
vuln:
    push ebp
    mov ebp, esp
    sub esp, 0x48
    push 0x12c
    lea eax, [ebp-0x40]
    push eax
    push 0
    call read
    add esp, 12
    leave
    ret
.size vuln, .-vuln

.globl read
.type read, @function
read:
    push ebp
    mov ebp, esp
    mov eax, 3
    mov ebx, [ebp+8]
    mov ecx, [ebp+12]
    mov edx, [ebp+16]
    int 0x80
    leave
    ret
.size read, .-read

.globl win
.type win, @function
win:
    mov eax, 11
    lea ebx, [binsh]
    xor ecx, ecx
    xor edx, edx
    int 0x80
    mov eax, 1
    xor ebx, ebx
    int 0x80
.size win, .-win

.globl sink
.type sink, @function
sink:
    push ebp
    mov ebp, esp
    leave
    ret
.size sink, .-sink

.globl demo
.type demo, @function
demo:
    push ebp
    mov ebp, esp
    push ebx
    push 0x41
    call sink
    pop ebx
    leave
    ret
.size demo, .-demo

.section .rodata
binsh:
    .asciz "/bin/sh"
.globl message
message:
    .asciz "PWNED"
