# tests/fixtures/i386_shellcode.s — 32-bit shellcode fixture with an executable stack
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
    push 0x100
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

# jmp esp gadget for the executable-stack shellcode path
g_jmp_esp:
    jmp esp
