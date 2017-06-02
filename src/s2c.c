
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <secp256k1.h>

#include "hash.h"
#include "s2c.h"
#include "util.h"

static int nonce_function_s2c_(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
    s2c_context *s2c_ctx = data;
    unsigned char pkbin[33];
    unsigned char tweak[32];
    size_t pklen = sizeof(pkbin);
    secp256k1_sha256_t sha2;
    secp256k1_sha256_initialize(&sha2);

    assert(data != NULL);

    /* Execute RFC6979 to get a "default" nonce */
    if (secp256k1_nonce_function_rfc6979(nonce32, msg32, key32, algo16, NULL, counter) == 0) {
        return 0;
    }

    /* Compute public nonce -- the calling code will also compute a public nonce, but a
     * tweaked one, and we need this one to compute the tweak, so the inefficiency here
     * is inherent to the problem. */
    if (secp256k1_ec_pubkey_create(s2c_ctx->ctx, &s2c_ctx->pk_ret, nonce32) == 0) {
        return 0;
    }

    /* Skew it */
    secp256k1_ec_pubkey_serialize(s2c_ctx->ctx, pkbin, &pklen, &s2c_ctx->pk_ret, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha2, pkbin, pklen);
    secp256k1_sha256_write(&sha2, s2c_ctx->msg, s2c_ctx->msg_len);
    secp256k1_sha256_finalize(&sha2, tweak);

    if (secp256k1_ec_privkey_tweak_add(s2c_ctx->ctx, nonce32, tweak) == 0) {
        return 0;
    }
    return 1;
}

const secp256k1_nonce_function nonce_function_s2c = nonce_function_s2c_;

/* Sign-to-contract signing */
void s2c_usage(const char *name) {
    fprintf(stderr, "  %s signtocontract <secret key> <hex-encoded commitment> <message>\n", name);
}

int s2c_command(int argc, char *argv[]) {
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature sig;
    unsigned char msg[32];
    unsigned char sk[32];
    s2c_context s2c_context;

    (void) argc;

    /* Parse secret key */
    if (strlen(argv[2]) != 64 || !hex2bin(argv[2], sk)) {
        fprintf(stderr, "secret key « %s » should be a 64-character hex string\n", argv[2]);
        return 0;
    }

    /* Parse extracommit */
    s2c_context.msg_len = strlen(argv[3]) / 2;
    s2c_context.msg = malloc(s2c_context.msg_len);
    if (s2c_context.msg == NULL) exit(EXIT_FAILURE);
    if (!hex2bin(argv[3], s2c_context.msg)) {
        fprintf(stderr, "Commit data appears not to be hex-encoded\n");
        return 0;
    }

    /* Parse message */
    if (strlen(argv[4]) == 64 && hex2bin(argv[4], msg)) {
        fprintf(stderr, "Note: message appears to be a 32-byte hex string, interpreting as hex rather than re-hashing.\n");
    } else {
        secp256k1_sha256_t sha2;
        secp256k1_sha256_initialize(&sha2);
        secp256k1_sha256_write(&sha2, (unsigned char*)argv[3], strlen(argv[3]));
        secp256k1_sha256_finalize(&sha2, msg);
    }

    /* Sign */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    s2c_context.ctx = ctx;
    if (secp256k1_ecdsa_sign(ctx, &sig, msg, sk, nonce_function_s2c_, &s2c_context)) {
        unsigned char sigbin[72];
        size_t siglen = sizeof(sigbin);

        if (secp256k1_ecdsa_signature_serialize_der(ctx, sigbin, &siglen, &sig)) {
            unsigned char pk[33];
            char pkhex[66];
            size_t pklen = sizeof(pk);
            char sighex[145];
            secp256k1_ec_pubkey_serialize(ctx, pk, &pklen, &s2c_context.pk_ret, SECP256K1_EC_COMPRESSED);
            bin2hex(pkhex, pk, pklen);
            bin2hex(sighex, sigbin, siglen);
            printf("%s\n", sighex);
            printf("%s\n", pkhex);
            free(s2c_context.msg);
            secp256k1_context_destroy(ctx);
            return 1;
        } else {
            fprintf(stderr, "Failed to serialize sig\n");
        }
    } else {
        fprintf(stderr, "Failed to sign message\n");
    }

    free(s2c_context.msg);
    secp256k1_context_destroy(ctx);
    return 0;
}

