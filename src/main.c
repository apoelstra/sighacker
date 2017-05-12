
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "command.h"

void full_usage(const char *name) {
    size_t i;
    fprintf(stderr, "Usage:\n");
    for (i = 0; i < NCOMMANDS; i++) {
        COMMANDS[i].usage(name);
    }
}

int main(int argc, char *argv[]) {
    if (argc >= 2) {
        size_t i;
        for (i = 0; i < NCOMMANDS; i++) {
            if (strcmp(argv[1], COMMANDS[i].name) == 0) {
                if ((size_t) argc >= COMMANDS[i].min_argc) {
                    return !COMMANDS[i].handle(argc, argv);
                } else {
                    fprintf(stderr, "Usage:\n");
                    COMMANDS[i].usage(argv[0]);
                    return EXIT_FAILURE;
                }
            }
        }
    }

    full_usage(argv[0]);
    return EXIT_FAILURE;
}

