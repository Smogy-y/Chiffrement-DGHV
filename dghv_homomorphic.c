#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Security parameters
#define LAMBDA 80  // Security parameter (bit length)
#define ETA 25     // Noise bit length
#define GAMMA 2048 // Ciphertext modulus bit length

mpz_t p; // Private key
mpz_t q0; // Public key component

// Key generation function
void keygen() {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_init(p);
    mpz_urandomb(p, state, LAMBDA); // Generate random private key p

    mpz_init(q0);
    mpz_urandomb(q0, state, GAMMA); // Generate random q0

    mpz_mul(q0, p, q0); // q0 = p * q0

    // Print keys for debugging
    gmp_printf("Private key (p): %Zd\n", p);
    gmp_printf("Public key (q0): %Zd\n", q0);

    gmp_randclear(state);
}

// Encryption function
void encrypt(mpz_t c, int m) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_t r, e;
    mpz_init(r);
    mpz_urandomb(r, state, ETA); // Generate small random noise r

    mpz_init(e);
    mpz_mul_si(e, p, m); // e = p * m
    mpz_add(e, e, r); // e = p * m + r
    mpz_mod(c, e, q0); // c = (p * m + r) mod q0

    gmp_randclear(state);
    mpz_clear(r);
    mpz_clear(e);

    // Print ciphertext for debugging
    gmp_printf("Ciphertext (c): %Zd\n", c);
}

// Decryption function
int decrypt(mpz_t c) {
    mpz_t m;
    mpz_init(m);
    mpz_mod(m, c, p); // m = c mod p

    int result = mpz_cmp_ui(m, 0); // Convert mpz_t to int
    mpz_clear(m);

    return result;
}

// Homomorphic addition function
void homomorphic_add(mpz_t result, mpz_t c1, mpz_t c2) {
    mpz_add(result, c1, c2);
    mpz_mod(result, result, q0); // result = (c1 + c2) mod q0
}

// Homomorphic multiplication function
void homomorphic_mul(mpz_t result, mpz_t c1, mpz_t c2) {
    mpz_mul(result, c1, c2);
    mpz_mod(result, result, q0); // result = (c1 * c2) mod q0
}

// Bootstrap function (simplified)
void bootstrap(mpz_t c) {
    // Placeholder function for bootstrap operation
    // In practice, this involves complex operations to refresh the ciphertext
    // For simplicity, we re-encrypt the decrypted value
    int m = decrypt(c);
    encrypt(c, m);
}

// Main function
int main() {
    // Initialize GMP library variables
    mpz_t c1, c2, c_add, c_mul;
    mpz_init(c1);
    mpz_init(c2);
    mpz_init(c_add);
    mpz_init(c_mul);

    // Generate keys
    keygen();

    // Encrypt messages (example with m1 = 1 and m2 = 0)
    int message1 = 1;
    int message2 = 0;
    encrypt(c1, message1);
    encrypt(c2, message2);

    // Perform homomorphic addition
    homomorphic_add(c_add, c1, c2);
    int decrypted_add = decrypt(c_add);
    printf("Decrypted addition result: %d\n", decrypted_add);

    // Perform homomorphic multiplication
    homomorphic_mul(c_mul, c1, c2);
    int decrypted_mul = decrypt(c_mul);
    printf("Decrypted multiplication result: %d\n", decrypted_mul);

    // Bootstrap the ciphertexts (optional, for illustration)
    bootstrap(c_add);
    bootstrap(c_mul);

    // Decrypt the bootstrapped ciphertexts
    decrypted_add = decrypt(c_add);
    printf("Decrypted addition result after bootstrap: %d\n", decrypted_add);

    decrypted_mul = decrypt(c_mul);
    printf("Decrypted multiplication result after bootstrap: %d\n", decrypted_mul);

    // Clear GMP variables
    mpz_clear(c1);
    mpz_clear(c2);
    mpz_clear(c_add);
    mpz_clear(c_mul);
    mpz_clear(p);
    mpz_clear(q0);

    return 0;
}