/* adversarial 3: PIE ON, no leak channel visible at first glance */
#include <stdio.h>
#include <unistd.h>
void loopback(void) {
    char b[80];
    puts("data:");
    read(0, b, 400);
    puts("ok");
}
int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    loopback();
    return 0;
}
