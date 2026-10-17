/* heap_uaf: 堆 UAF + tcache poisoning
 * 题解: free 后仍可写 -> tcache double-free/poisoning
 *       令 tcache next 指向 __free_hook, 写 system, free("/bin/sh")
 * 需要 glibc 2.31 以下或适配 tcache (无 key 检查绕过时用 double free)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct { char *ptr; size_t size; } slots[8];

void menu(void) {
    puts("1. add  2. del  3. edit  4. show  5. exit");
    printf("> ");
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    int n, idx; char tmp[32];
    while (1) {
        menu();
        if (!fgets(tmp, sizeof(tmp), stdin)) break;
        n = atoi(tmp);
        if (n == 1) {
            printf("idx: ");
            fgets(tmp, sizeof(tmp), stdin); idx = atoi(tmp);
            printf("size: ");
            fgets(tmp, sizeof(tmp), stdin);
            slots[idx].size = strtoul(tmp, 0, 10);
            slots[idx].ptr = malloc(slots[idx].size);
            printf("data: ");
            read(0, slots[idx].ptr, slots[idx].size);
        } else if (n == 2) {
            printf("idx: ");
            fgets(tmp, sizeof(tmp), stdin); idx = atoi(tmp);
            free(slots[idx].ptr);
            /* bug: 未置空指针 -> UAF (dangling pointer) */
        } else if (n == 3) {
            printf("idx: ");
            fgets(tmp, sizeof(tmp), stdin); idx = atoi(tmp);
            printf("data: ");
            read(0, slots[idx].ptr, slots[idx].size); /* write-after-free */
        } else if (n == 4) {
            printf("idx: ");
            fgets(tmp, sizeof(tmp), stdin); idx = atoi(tmp);
            puts(slots[idx].ptr); /* read-after-free, 可泄露 */
        } else break;
    }
    return 0;
}
