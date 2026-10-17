// 64-bit heap menu where the menu loop lives in a helper function (not main).
//   gcc -O2 -fno-inline -fno-stack-protector -no-pie -o heap_menu_helper heap_menu_helper.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *chunks[16];
static int cnt = 0;

void win(void) { system("/bin/sh"); }

static void add(void) {
    void *p;
    if (cnt >= 16) return;
    p = malloc(0x20);
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
    if (i < (unsigned)cnt) free(chunks[i]);
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
        read(0, chunks[i], 0x80);
    }
}

static void menu_loop(void) {
    char choice[8];
    for (;;) {
        printf("1. omega\n2. psi\n3. chi\n4. phi\n5. exit\n> ");
        if (!fgets(choice, sizeof choice, stdin)) break;
        switch (choice[0]) {
        case '1': add();  break;
        case '2': dele(); break;
        case '3': show(); break;
        case '4': edit(); break;
        default: return;
        }
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    menu_loop();
    return 0;
}
