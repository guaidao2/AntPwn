// PIE + backdoor, no address leak: used to verify partial return-address overwrite.
//   gcc -pie -fpie -fno-stack-protector -o pie_partial pie_partial.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) { system("/bin/sh"); }

void vuln(void) {
    char b[64];
    puts("data:");
    read(0, b, 200);
}

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    vuln();
    return 0;
}
