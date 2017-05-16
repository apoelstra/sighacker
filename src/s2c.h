#ifndef SIGHACKER_S2C_H
#define SIGHACKER_S2C_H

#include <secp256k1.h>

typedef struct {
    secp256k1_context *ctx;
    unsigned char *msg;
    size_t msg_len;
    secp256k1_pubkey pk_ret;
} s2c_context;

void s2c_usage(const char *name);

int s2c_command(int argc, char *argv[]);

#endif
