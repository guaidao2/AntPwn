// i386 format-string fixture: loop + printf(buf) + backdoor win
// build: gcc -m32 -fno-stack-protector -no-pie -o i386_fmt i386_fmt.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    system("/bin/sh");
}

int main(void) {
    char buf[128];
    setbuf(stdout, NULL);
    while (1) {
        printf("input: ");
        if (!fgets(buf, sizeof buf, stdin))
            break;
        printf(buf);
        printf("\n");
    }
    return 0;
}
