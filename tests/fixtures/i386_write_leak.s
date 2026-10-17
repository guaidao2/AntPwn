# i386 ret2libc with only write() available (no puts).
# build: gcc -m32 -no-pie -fno-stack-protector -o i386_write_leak i386_write_leak.s
    .section .rodata
msg:
    .asciz "hi\n"
    .text
    .globl main
    .type main, @function
main:
    pushl %ebp
    movl %esp, %ebp
    subl $0x60, %esp
    pushl $3
    pushl $msg
    pushl $1
    call write@plt
    addl $0xc, %esp
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
