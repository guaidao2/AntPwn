// i386 format-string with no backdoor: printf(buf) loop -> libc leak path.
// gcc -m32 -fno-stack-protector -no-pie -o i386_fmt_libc i386_fmt_libc.c
#include <stdio.h>
#include <unistd.h>
int main(void) {
    char buf[128];
    setbuf(stdout, NULL);
    while (fgets(buf, sizeof buf, stdin)) {
        printf(buf);
    }
    return 0;
}
