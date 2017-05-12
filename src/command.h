#ifndef SIGHACKER_COMMAND_H
#define SIGHACKER_COMMAND_H

#include <stddef.h>

typedef struct {
    const char *name;
    size_t min_argc;
    void (*usage)(const char *);
    int (*handle)(int, char **);
} cli_command;

extern cli_command COMMANDS[];
extern const size_t NCOMMANDS;

#endif
