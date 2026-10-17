# i386 shellcode fixture: leaked stack buffer address, exec stack, no jmp esp needed.
# build: gcc -m32 -no-pie -z execstack -fno-stack-protector -o i386_shellcode_leak i386_shellcode_leak.s
    .section .rodata
fmt:
    .asciz "buf: %p\n"
    .text
    .globl main
    .type main, @function
main:
    pushl %ebp
    movl %esp, %ebp
    subl $0x60, %esp
    leal -0x60(%ebp), %eax
    pushl %eax
    pushl $fmt
    call printf@plt
    addl $8, %esp
    pushl $0x200
    leal -0x60(%ebp), %eax
    pushl %eax
    pushl $0
    call read@plt
    addl $0xc, %esp
    leave
    ret
    .size main, .-main
    .section .note.GNU-stack,"",@progbits
