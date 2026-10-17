// tests/fixtures/i386_ret2libc.c — 32-bit dynamic fixture for the i386 cdecl
// ret2libc chain (built with gcc -m32 when 32-bit libc headers/libs exist)
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];
    puts("name:");
    read(0, buf, 300);
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
