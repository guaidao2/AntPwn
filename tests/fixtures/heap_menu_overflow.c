// 64-bit menu heap-overflow fixture (scanner/exploit verification):
//   gcc -fno-stack-protector -no-pie -o heap_menu_overflow heap_menu_overflow.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *chunks[16];
static int cnt = 0;

void win(void) { system("/bin/sh"); }   // ensures system@plt exists

static void add(void) {
    if (cnt >= 16) return;
    void *p = malloc(0x20);
    chunks[cnt] = p;
    printf("chunk[%d] @ %p\n", cnt, p);
    printf("data: ");
    read(0, p, 8);
    cnt++;
}

static void dele(void) {
    unsigned i;
    printf("idx: ");
    if (scanf("%u", &i) != 1) return;
    getchar();
    if (i < (unsigned)cnt) free(chunks[i]);   // not nulled: UAF too
}

static void show(void) {
    unsigned i;
    printf("idx: ");
    if (scanf("%u", &i) != 1) return;
    getchar();
    if (i < (unsigned)cnt) write(1, chunks[i], 8);
}

static void edit(void) {
    unsigned i;
    printf("idx: ");
    if (scanf("%u", &i) != 1) return;
    getchar();
    if (i < (unsigned)cnt) {
        printf("data: ");
        read(0, chunks[i], 0x80);   // heap overflow: chunk is only 0x20 bytes
    }
}

int main(void) {
    char choice[8];
    setbuf(stdout, NULL);
    for (;;) {
        printf("1. alpha\n2. beta\n3. gamma\n4. delta\n5. exit\n> ");
        if (!fgets(choice, sizeof choice, stdin)) break;
        switch (choice[0]) {
        case '1': add();  break;
        case '2': dele(); break;
        case '3': show(); break;
        case '4': edit(); break;
        default: return 0;
        }
    }
    return 0;
}
