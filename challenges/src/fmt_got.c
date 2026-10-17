/* fmt_got: 格式化字符串漏洞, 循环 printf(buf)
 * 题解: 用 %hn 两次写, 覆写 printf@got -> win(), 下轮循环 getshell
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void win(void) { system("/bin/sh"); }

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    char buf[160];
    while (1) {
        memset(buf, 0, sizeof(buf));
        read(0, buf, 128);
        if (buf[0] == 'q') break;
        printf(buf);
        puts("|end");
    }
    return 0;
}
