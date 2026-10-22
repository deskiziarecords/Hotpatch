// src/rot/rot_cli.c
// Test/diff harness: plays the root-of-trust. Verifies the cert's Ed25519
// signature and prints the latched SHA-256 digest (hex), or REFUSED.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "rot_attest.h"

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + i * 2, "%02hhx", &bytes[i]) != 1) return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <cert_path> <pubkey_hex>\n", argv[0]);
        return 2;
    }

    uint8_t pubkey[32];
    if (hex_to_bytes(argv[2], pubkey, 32) != 0) {
        fprintf(stderr, "Invalid pubkey hex\n");
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 2;
    }

    uint8_t cert[HP_CERT_SIZE];
    if (fread(cert, 1, HP_CERT_SIZE, f) != HP_CERT_SIZE) {
        fprintf(stderr, "Failed to read 512-byte certificate\n");
        fclose(f);
        return 2;
    }
    fclose(f);

    hp_rot_latch_t latch;
    if (!hp_rot_attest(cert, pubkey, &latch)) {
        printf("REFUSED\n");
        return 1;
    }
    for (int i = 0; i < 32; ++i) printf("%02x", latch.digest[i]);
    printf("\n");
    return 0;
}
