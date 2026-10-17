// PIE heap menu that prints win only on the FIRST add (not at startup):
// HeapMenu must recover the base from later action output.
//   gcc -fpie -pie -fno-stack-protector -o heap_menu_pie_late heap_menu_pie_late.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *chunks[16];
static int cnt = 0;

void win(void) { system("/bin/sh"); }

static void add(void) {
    void *p;
    if (cnt >= 16) return;
    if (cnt == 0) printf("hint: %p\n", (void *)win);
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

int main(void) {
    char choice[8];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        printf("1. one\n2. two\n3. three\n4. four\n5. exit\n> ");
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
