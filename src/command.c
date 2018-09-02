
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "command.h"
#include "hash.h"
#include "s2c.h"
#include "util.h"

/* Public key generation */
static void pk_usage(const char *name) {
    fprintf(stderr, "  %s publickey <hex-encoded secret key>\n", name);
}

static int pk_command(int argc, char *argv[]) {
    unsigned char sk[32];
    secp256k1_pubkey pk;
    secp256k1_context *ctx;
    int ret;

    (void) argc;

    /* Parse secret key */
    if (strlen(argv[2]) != 64 || !hex2bin(argv[2], sk)) {
        fprintf(stderr, "secret key « %s » should be a 64-character hex string\n", argv[2]);
        return 0;
    }

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (secp256k1_ec_pubkey_create(ctx, &pk, sk)) {
        unsigned char binpk[33];
        size_t lenpk = sizeof(binpk);
        char hexpk[67];

        secp256k1_ec_pubkey_serialize(ctx, binpk, &lenpk, &pk, SECP256K1_EC_COMPRESSED);
        bin2hex(hexpk, binpk, lenpk);
        printf("%s\n", hexpk);
        ret = 1;
    } else {
        fprintf(stderr, "Failed to create pubkey\n");
        ret = 0;
    }

    secp256k1_context_destroy(ctx);
    return ret;
}

/* Signing */
static void sign_usage(const char *name) {
    fprintf(stderr, "  %s sign <secret key> <message>\n", name);
}

static int sign_command(int argc, char *argv[]) {
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature sig;
    unsigned char msg[32];
    unsigned char sk[32];

    (void) argc;

    /* Parse secret key */
    if (strlen(argv[2]) != 64 || !hex2bin(argv[2], sk)) {
        fprintf(stderr, "secret key « %s » should be a 64-character hex string\n", argv[2]);
        return 0;
    }

    /* Parse message */
    if (strlen(argv[3]) == 64 && hex2bin(argv[3], msg)) {
        fprintf(stderr, "Note: message appears to be a 32-byte hex string, interpreting as hex rather than re-hashing.\n");
    } else {
        secp256k1_sha256_t sha2;
        secp256k1_sha256_initialize(&sha2);
        secp256k1_sha256_write(&sha2, (unsigned char*)argv[3], strlen(argv[3]));
        secp256k1_sha256_finalize(&sha2, msg);
    }

    /* Sign */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (secp256k1_ecdsa_sign(ctx, &sig, msg, sk, NULL, NULL)) {
        unsigned char sigbin[72];
        size_t siglen = sizeof(sigbin);

        if (secp256k1_ecdsa_signature_serialize_der(ctx, sigbin, &siglen, &sig)) {
            char sighex[145];
            bin2hex(sighex, sigbin, siglen);
            printf("%s\n", sighex);
            secp256k1_context_destroy(ctx);
            return 1;
        } else {
            fprintf(stderr, "Failed to serialize sig\n");
        }
    } else {
        fprintf(stderr, "Failed to sign message\n");
    }

    secp256k1_context_destroy(ctx);
    return 0;
}

/* Verification */
static void verify_usage(const char *name) {
    fprintf(stderr, "  %s verify <public key> <signature> <message>\n", name);
}

static int verify_command(int argc, char *argv[]) {
    unsigned char msg[32];
    unsigned char pkbin[33];
    unsigned char sigbin[72];
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    size_t siglen;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    (void) argc;

    /* Parse public key */
    if (strlen(argv[2]) != 66 || !hex2bin(argv[2], pkbin)) {
        fprintf(stderr, "public key « %s » should be a 66-character hex string\n", argv[2]);
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pkbin, sizeof(pkbin))) {
        fprintf(stderr, "public key « %s » is invalid\n", argv[2]);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* Parse signature */
    if (strlen(argv[3]) > 2 * sizeof(sigbin)) {
        fprintf(stderr, "signature « %s » exceeds maximum length\n", argv[3]);
        secp256k1_context_destroy(ctx);
        return 0;
    }
    siglen = hex2bin(argv[3], sigbin);
    if (siglen == 0) {
        fprintf(stderr, "signature « %s » should be a hex string\n", argv[3]);
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbin, siglen)) {
        fprintf(stderr, "signature « %s » should be a DER-encoded hex string\n", argv[3]);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* Parse message */
    if (strlen(argv[4]) == 64 && hex2bin(argv[4], msg)) {
        fprintf(stderr, "Note: message appears to be a 32-byte hex string, interpreting as hex rather than re-hashing.\n");
    } else {
        secp256k1_sha256_t sha2;
        secp256k1_sha256_initialize(&sha2);
        secp256k1_sha256_write(&sha2, (unsigned char*)argv[4], strlen(argv[4]));
        secp256k1_sha256_finalize(&sha2, msg);
    }

    /* Verify */
    if (secp256k1_ecdsa_verify(ctx, &sig, msg, &pk)) {
        puts("Valid signature.");
        secp256k1_context_destroy(ctx);
        return 1;
    } else {
        puts("Invalid signature.");
        secp256k1_context_destroy(ctx);
        return 0;
    }
}

/* Pubkey recovery */
static void recoverpk_usage(const char *name) {
    fprintf(stderr, "  %s recoverpubkey <signature> <message>\n", name);
}

static int recoverpk_command(int argc, char *argv[]) {
    unsigned char msg[32];
    unsigned char sigbin[72];
    unsigned char compact_sig[64];
    unsigned char pkbin[33];
    size_t publen = 33;
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;
    secp256k1_ecdsa_recoverable_signature recsig;
    size_t siglen;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    int recid;
    int recovered = 0;

    (void) argc;

    /* Parse signature */
    if (strlen(argv[2]) > 2 * sizeof(sigbin)) {
        fprintf(stderr, "signature « %s » exceeds maximum length\n", argv[2]);
        secp256k1_context_destroy(ctx);
        return 0;
    }
    siglen = hex2bin(argv[2], sigbin);
    if (siglen == 0) {
        fprintf(stderr, "signature « %s » should be a hex string\n", argv[2]);
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, sigbin, siglen)) {
        fprintf(stderr, "signature « %s » should be a DER-encoded hex string\n", argv[2]);
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, compact_sig, &sig)) {
        fprintf(stderr, "signature could not be re-encoded as comapct\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* Parse message */
    if (strlen(argv[3]) == 64 && hex2bin(argv[3], msg)) {
        fprintf(stderr, "Note: message appears to be a 32-byte hex string, interpreting as hex rather than re-hashing.\n");
    } else {
        secp256k1_sha256_t sha2;
        secp256k1_sha256_initialize(&sha2);
        secp256k1_sha256_write(&sha2, (unsigned char*)argv[3], strlen(argv[3]));
        secp256k1_sha256_finalize(&sha2, msg);
    }

    /* Recover */
    /* Try all recids */
    for (recid = 0; recid < 4; ++recid) {
        if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &recsig, compact_sig, recid)) {
            fprintf(stderr, "Unable to parse compact signature with recid %d\n", recid);
            secp256k1_context_destroy(ctx);
            return 0;
        }
        if (secp256k1_ecdsa_recover(ctx, &pk, &recsig, msg)) {
            secp256k1_ec_pubkey_serialize(ctx, pkbin, &publen, &pk, SECP256K1_EC_COMPRESSED);
            char pubhex[131];
            bin2hex(pubhex, pkbin, publen);
            printf("recid: %d, pubkey: %s\n", recid, pubhex);
            recovered = 1;
        }
    }
    if (recovered) {
        secp256k1_context_destroy(ctx);
        return 1;
    } else {
        puts("Unable to recover pubkey from signature.");
        secp256k1_context_destroy(ctx);
        return 0;
    }
}

cli_command COMMANDS[] = {
    { "publickey", 3, pk_usage, pk_command },
    { "recoverpubkey", 4, recoverpk_usage, recoverpk_command },
    { "sign", 4, sign_usage, sign_command },
    { "signtocontract", 5, s2c_usage, s2c_command },
    { "verify", 5, verify_usage, verify_command }
};
const size_t NCOMMANDS = sizeof(COMMANDS) / sizeof(COMMANDS[0]);

