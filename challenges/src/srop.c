/* srop: read 溢出, 但 gadgets 极少 -> SROP
 * 题解: 溢出 -> rt_sigreturn(15) syscall -> 伪造 SignalFrame{rax=59, rdi="/bin/sh"}
 */
#include <unistd.h>
#include <stdio.h>

const char *sh = "/bin/sh";

void vuln(void) {
    char buf[64];
    read(0, buf, 512);
    /* 编译时确保有一个 syscall gadget 可用 (gadgets.S 提供) */
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
