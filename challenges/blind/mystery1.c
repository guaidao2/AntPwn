/* blind test 1: no backdoor, no /bin/sh, plain gcc, odd names */
#include <stdio.h>
#include <unistd.h>

void data_processor(void) {
    char local_cache[100];
    puts("gimme bytes");
    read(0, local_cache, 400);
    puts("done");
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    data_processor();
    return 0;
}

/* typical CTF "gadget barn" (authors always leave some) */
__asm__(".globl gad1\n gad1: pop %rdi; ret\n"
        ".globl gad2\n gad2: pop %rsi; pop %r15; ret\n"
        ".globl gad3\n gad3: pop %rdx; ret\n");
