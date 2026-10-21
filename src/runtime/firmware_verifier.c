#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "verify_cert.h"
#include "hmac_sha256.h"

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + i * 2, "%02hhx", &bytes[i]) != 1) return -1;
    }
    return 0;
}

// Test/diff harness only. On a device the anchor lives in unwritable storage,
// the epoch comes from a monotonic counter, and the MAC key is sealed in
// hardware; none of them come from the command line.
typedef struct {
    uint64_t stored_epoch;
    uint8_t  mac_key[32];
} cli_platform_t;

static uint64_t cli_read_epoch(void *ctx) {
    return ((cli_platform_t *)ctx)->stored_epoch;
}

static int cli_advance_epoch(void *ctx, uint64_t epoch) {
    (void)ctx;
    (void)epoch;
    return 0; // verify-only harness never advances
}

static void cli_mac(void *ctx, const uint8_t *msg, size_t len, uint8_t out[32]) {
    cli_platform_t *p = ctx;
    hmac_sha256(p->mac_key, sizeof(p->mac_key), msg, len, out);
}

int main(int argc, char *argv[]) {
    if (argc != 9) {
        fprintf(stderr, "Usage: %s <cert_path> <key_id_hex> <max_wcet_ns> <max_budget> <max_agents> <max_leakage> <stored_epoch> <mac_key_hex>\n", argv[0]);
        return 2;
    }

    const char *cert_path = argv[1];
    const char *key_id_hex = argv[2];

    hp_anchor_t anchor;
    anchor.max_wcet_ns = strtoull(argv[3], NULL, 10);
    anchor.max_budget = strtoull(argv[4], NULL, 10);
    anchor.max_agents = (uint8_t)atoi(argv[5]);
    anchor.max_leakage = (uint8_t)atoi(argv[6]);

    cli_platform_t plat;
    plat.stored_epoch = strtoull(argv[7], NULL, 10);
    if (hex_to_bytes(argv[8], plat.mac_key, 32) != 0) {
        fprintf(stderr, "Invalid mac_key hex\n");
        return 2;
    }
    anchor.read_epoch = cli_read_epoch;
    anchor.advance_epoch = cli_advance_epoch;
    anchor.mac = cli_mac;
    anchor.ctx = &plat;

    if (hex_to_bytes(key_id_hex, anchor.key_id, 32) != 0) {
        fprintf(stderr, "Invalid key_id hex\n");
        return 2;
    }

    FILE *f = fopen(cert_path, "rb");
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

    int res = verify_cert(cert, &anchor);

    if (res == 1) {
        printf("VERIFIED\n");
        return 0;
    } else {
        printf("REJECTED\n");
        return 1;
    }
}
