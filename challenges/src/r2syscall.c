/* ret2syscall: ROP 到 execve("/bin/sh",0,0) 系统调用
 * 需要 pop rdi/rsi/rdx/rax + syscall gadgets
 */
#include <unistd.h>
#include <stdio.h>

const char *sh = "/bin/sh";

void vuln(void) {
    char buf[64];
    read(0, buf, 256);
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
