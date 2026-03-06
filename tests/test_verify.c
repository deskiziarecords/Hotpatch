// tests/test_verify.c
// Small test harness that generates a test cert and runs the verifier.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/runtime/verify_cert.h"

// helper to build a valid cert in memory
void build_valid_cert(uint8_t cert[512]) {
    memset(cert, 0, 512);
    // pubkey hash zeros (matches expected_pub)
    // set wcet at 0xB0 (150,000 ns)
    uint64_t wcet = 150000ull;
    for (int i = 7; i >= 0; --i) {
        cert[0xB0 + i] = (uint8_t)(wcet & 0xFF);
        wcet >>= 8;
    }
    uint64_t deltaB = 1000ull;
    for (int i = 7; i >= 0; --i) {
        cert[0xB8 + i] = (uint8_t)(deltaB & 0xFF);
        deltaB >>= 8;
    }
    cert[0xC0] = 5; // A
    cert[0xC1] = 50; // epsilon
}

int main(void) {
    uint8_t cert[512];
    build_valid_cert(cert);
    uint8_t expected_pub[32];
    memset(expected_pub, 0, sizeof(expected_pub));

    // Valid case
    int res = verify_cert(cert, expected_pub, 150000ull, 10000ull, 5, 100);
    printf("verify result (valid): %d (expected 1)\n", res);

    // Now tamper pubhash
    cert[0] = 1;
    res = verify_cert(cert, expected_pub, 150000ull, 10000ull, 5, 100);
    printf("verify result after tamper (pubhash): %d (expected 0)\n", res);
    cert[0] = 0; // restore

    // Exceed wcet
    uint64_t wcet_orig = 150000ull;
    uint64_t wcet_too_large = 200000ull;
    for (int i = 7; i >= 0; --i) {
        cert[0xB0 + i] = (uint8_t)(wcet_too_large & 0xFF);
        wcet_too_large >>= 8;
    }
    res = verify_cert(cert, expected_pub, 150000ull, 10000ull, 5, 100);
    printf("verify result after exceed wcet: %d (expected 0)\n", res);
    // restore wcet
    for (int i = 7; i >= 0; --i) {
        cert[0xB0 + i] = (uint8_t)(wcet_orig & 0xFF);
        wcet_orig >>= 8;
    }

    // Exceed budget
    uint64_t budget_too_large = 11000ull;
    for (int i = 7; i >= 0; --i) {
        cert[0xB8 + i] = (uint8_t)(budget_too_large & 0xFF);
        budget_too_large >>= 8;
    }
    res = verify_cert(cert, expected_pub, 150000ull, 10000ull, 5, 100);
    printf("verify result after exceed budget: %d (expected 0)\n", res);
    // restore budget
    uint64_t budget_orig = 1000ull;
    for (int i = 7; i >= 0; --i) {
        cert[0xB8 + i] = (uint8_t)(budget_orig & 0xFF);
        budget_orig >>= 8;
    }

    // Exceed agents
    cert[0xC0] = 6;
    res = verify_cert(cert, expected_pub, 150000ull, 10000ull, 5, 100);
    printf("verify result after exceed agents: %d (expected 0)\n", res);
    cert[0xC0] = 5; // restore

    // Exceed epsilon
    cert[0xC1] = 101;
    res = verify_cert(cert, expected_pub, 150000ull, 10000ull, 5, 100);
    printf("verify result after exceed epsilon: %d (expected 0)\n", res);
    cert[0xC1] = 50; // restore

    return 0;
}
