/* adversarial 1 (realistic): -O2 optimized, odd names, puts prompt exists */
#include <stdio.h>
#include <unistd.h>
void entry_point(void) {
    char scratch[72];
    puts("feed me");
    read(0, scratch, 300);
    puts("done");
}
int main(void) {
    setvbuf(stdout, 0, 2, 0);
    entry_point();
    return 0;
}

/* gadget barn, as real CTF authors leave */
__asm__(".globl gad1\n gad1: pop %rdi; ret\n"
        ".globl gad2\n gad2: pop %rsi; pop %r15; ret\n"
        ".globl gad3\n gad3: pop %rdx; ret\n");
