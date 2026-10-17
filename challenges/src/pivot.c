/* pivot: 溢出空间极小 (只有 0x18 = 3 个字), 无法放下完整 ROP 链
 * 题解: 第一次 read 写入可控的 bss 缓冲区 + ROP 链,
 *       第二次溢出 -> leave;ret 把 rsp 迁移到 bss 继续执行
 */
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char stage[0x200]; /* bss 上的跳板 */

void vuln(void) {
    char buf[16];
    puts("stage1: write rop chain");
    read(0, stage, 0x200);
    puts("stage2: overflow");
    read(0, buf, 0x20); /* 只能覆盖 rbp + ret */
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
