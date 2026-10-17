/* blind test 2: format string, NO backdoor, generic libc path required */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    char note[200];
    while (1) {
        memset(note, 0, sizeof(note));
        if (read(0, note, 150) <= 0) break;
        if (note[0] == 'Q') break;
        printf(note);
        fflush(stdout);
    }
    return 0;
}
