// 64-bit heap-overflow fixture used for scanner verification (build manually):
//   gcc -fno-stack-protector -no-pie -o heap_overflow heap_overflow.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char *p = malloc(0x20);
    read(0, p, 0x100);          // heap overflow: 0x100 into malloc(0x20)
    write(1, p, 0x20);
    free(p);
    char *q = malloc(0x40);
    read(0, q, 0x41);           // off-by-one: 0x41 into malloc(0x40)
    free(q);
    return 0;
}
