// 64-bit menu fixture with a dense switch -> gcc -O2 usually emits a jump table.
//   gcc -O2 -fno-stack-protector -no-pie -o heap_menu_jumptable heap_menu_jumptable.c
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

static void nop1(void) { puts("1"); }
static void nop2(void) { puts("2"); }
static void nop3(void) { puts("3"); }
static void nop4(void) { puts("4"); }

int main(void) {
    char choice[8];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        printf("1. alpha\n2. beta\n3. gamma\n4. delta\n5. epsilon\n"
               "6. zeta\n7. eta\n8. theta\n9. exit\n> ");
        if (!fgets(choice, sizeof choice, stdin)) break;
        switch (choice[0]) {
        case '1': add();     break;
        case '2': dele();    break;
        case '3': show();    break;
        case '4': edit();    break;
        case '5': nop1();    break;
        case '6': nop2();    break;
        case '7': nop3();    break;
        case '8': nop4();    break;
        default: return 0;
        }
    }
    return 0;
}
