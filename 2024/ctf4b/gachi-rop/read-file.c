#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        puts("./read-file <PATH>");
        exit(1);
    }

    char buf[0x50];
    int fd  = open(argv[1], O_RDONLY);
    read(fd, buf, 0x50);
    puts(buf);
}