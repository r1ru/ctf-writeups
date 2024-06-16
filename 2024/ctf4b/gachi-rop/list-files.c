#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        puts("./list-files <PATH>");
        exit(1);
    }

    DIR *dir = opendir(argv[1]);
    struct dirent *dp = readdir(dir);

    while (dp != NULL) {
        printf("%s\n", dp->d_name);
        dp = readdir(dir);
    }

    return 0;
} 