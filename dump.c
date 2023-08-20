#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void dump(uint64_t x) {
    char buffer[32];
    size_t buf_sz = 0;
    buffer[sizeof(buffer) - buf_sz - 1] = '\n';
    buf_sz++;

    do {
        buffer[sizeof(buffer) - buf_sz - 1] = (x % 10) + '0';
        buf_sz++;
        x /= 10;
    } while(x);

    write(1, &buffer[sizeof(buffer) - buf_sz], buf_sz);
}

int main(void) {
    dump(0);
    dump(21);
    dump(10);
    dump(2003);
    dump(2003);
    return 0;
}