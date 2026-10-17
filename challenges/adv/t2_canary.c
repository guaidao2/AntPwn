/* adversarial 2: stack protector ON — overflow present but canary blocks */
#include <stdio.h>
#include <unistd.h>
void handler(void) {
    char buf[64];
    puts("go");
    read(0, buf, 300);
}
int main(void) {
    setvbuf(stdout, 0, 2, 0);
    handler();
    return 0;
}
