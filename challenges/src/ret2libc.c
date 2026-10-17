/* ret2libc: NX on, need GOT leak + two-stage ROP
 * 阶段1: 溢出 -> puts(puts@got) 泄露 libc 基址, 返回 vuln
 * 阶段2: system("/bin/sh")
 */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[0x50];
    puts("input>");
    read(0, buf, 0x200);
    puts("received");
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    puts("bye");
    return 0;
}
