/* baby_bof: classic stack overflow -> ret2text
 * 题解: gets() 无边界检查, 溢出覆盖返回地址跳到 win()
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) { system("/bin/sh"); }

void vuln(void) {
    char buf[64];
    puts("Tell me your name:");
    gets(buf);
    puts("bye~");
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
