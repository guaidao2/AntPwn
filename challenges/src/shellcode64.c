/* shellcode64: 栈可执行 (execstack), read 溢出
 * 题解: ret -> jmp rsp gadget, rsp 处放 execve("/bin/sh") shellcode
 */
#include <unistd.h>
#include <stdio.h>

void vuln(void) {
    char buf[64];
    read(0, buf, 512);
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
