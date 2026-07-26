#define _GNU_SOURCE
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s USERNAME\n", argv[0]);
        return EXIT_FAILURE;
    }
    char *password = getpass("New demonstration password: ");
    char *hash = crypt(password, "$6$rounds=100000$st5039demo$");
    if (!hash)
        return EXIT_FAILURE;
    printf("%s:%s\n", argv[1], hash);
    return EXIT_SUCCESS;
}
