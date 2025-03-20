/* shainc.c - sha256, avoid namespace collisions */

/*
gcc shainc.c --std=c89 -Wall -Wextra -Werror -Wpedantic -O2 -o shainc
*/

#include <stdio.h>  /* fileio   */
#include <stdint.h> /* uint32_t */
#include <stdlib.h> /* exit     */
#include <string.h> /* memcpy   */


/* round constants */
/* network endian */
uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint32_t htonl(uint32_t n) {
    uint8_t swap;
    uint8_t *arr = (uint8_t *)&n;
    size_t i, j = sizeof(uint32_t) - 1;
    for (i = 0; i < 2; i++) {
        swap = arr[i];
        arr[i] = arr[j-i];
        arr[j-i] = swap;
    }
    return n;
}

/* endianness */
void end32a(uint32_t *a, size_t l) {
    size_t i;
    for (i = 0; i < l; i++) {
        a[i] = htonl(a[i]);
    }
}

uint64_t htonll(uint64_t n) {
    uint8_t swap;
    uint8_t *arr = (uint8_t *)&n;
    size_t i, j = sizeof(uint64_t) - 1;
    for (i = 0; i < 4; i++) {
        swap = arr[i];
        arr[i] = arr[j-i];
        arr[j-i] = swap;
    }
    return n;
}

/* Non-compliant due to use of `%b` 
void printa(uint32_t *a, size_t l) {
    size_t i;
    printf("Printing word array at location %p of size %lu...\n", (void *)a, l);
    fflush(stdout);
    for (i = 0; i < l; i++) {
        printf("w%02lu: %032b %08x\n", i, a[i], a[i]);
    }
}
*/

/* Can use #include "macros.h"
 * or...
 * lc/uc = upper/lower case
 * sig   = sigma
 * 0/1   = 0/1
 */
uint32_t choice(uint32_t a, uint32_t b, uint32_t c) {
    return ((a & b) ^ (~a & c));
}
uint32_t median(uint32_t a, uint32_t b, uint32_t c)  {
    return (a & b) ^ (a & c) ^ (b & c);
}
uint32_t rotate(uint32_t a, uint32_t b) {
    return ((a >> b) | (a << (32-b)));
}

uint32_t ucsig0(uint32_t u) {
    return rotate(u, 02) ^ rotate(u, 13) ^ rotate(u, 22);
}
uint32_t ucsig1(uint32_t u) {
    return rotate(u, 06) ^ rotate(u, 11) ^ rotate(u, 25);
}
uint32_t lcsig0(uint32_t u) {
    return rotate(u, 07) ^ rotate(u, 18) ^ (u >> 03);
}
uint32_t lcsig1(uint32_t u) {
    return rotate(u, 17) ^ rotate(u, 19) ^ (u >> 10);
}

/* Update hash h_i by processing message chunk m_i */
void chunks(uint8_t *m, uint32_t *h) {
    uint32_t w[64];
    size_t i;
    /* "working variables" */
    uint32_t a[8]; /* working */
    uint32_t t; /* temp for sigma calc */
    /* copy message in message schedule array */
    memcpy(w, m, 64);
    /* network endian */
    end32a(w, 16);
    for (i = 16; i < 64; i++) {
        w[i] = w[i-16] + lcsig0(w[i-15]) + w[i-7] + lcsig1(w[i-2]);
    }
    memcpy(a, h, 32);
    for (i = 0; i < 64; i++) {
        t = a[7] + ucsig1(a[4]) + choice(a[4], a[5], a[6]) + k[i] + w[i];
        a[7] = a[6];
        a[6] = a[5];
        a[5] = a[4];
        a[4] = a[3] + t;
        t += ucsig0(a[0]) + median(a[0], a[1], a[2]);
        a[3] = a[2];
        a[2] = a[1];
        a[1] = a[0];
        a[0] = t;
    }
    for (i = 0; i < 8; i++) {
        h[i] += a[i];
    }
    return;
}

/* hash function
*
 * Given a filename
 * Grab chunks of appropriate size
 * Apply an SHA256 round
 * Load the hash back into `hashed` when out of chunks
 */
void hash_f(char *f_name, uint32_t *hashed) {
    size_t read_l;
    uint8_t m[64];
    uint64_t l = 0;
    /* initial hash values (h_0) */
    /* network endian */
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    FILE *fp = fopen(f_name, "r"); /* read mode */

    if (fp == NULL) {
        fprintf(stderr, "fopen fails on f_name \"%s\", exiting...\n", f_name);
        exit(1);
    }

    do {
        memset(m, 0, 64);
        read_l = fread(m, 1, 64, fp);
        l += read_l;

        /* Check for padding cases... */
        if (read_l < 64) {
            /* network endian */
            m[read_l] = 0x80;
            /* Need 65 bits for l - that's 9 bytes, 64-9 = 55 */
            if (read_l > 55) {
                /* Two remaining chunks */
                chunks(m, h);
                /* Ultimate chunk is padding only */
                memset(m, 0, 64);
            }
            /* Convert l bytes->bits and place in the last 8 bytes / 64 bits */
            /* network endian */
            l = htonll(l << 3);
            memcpy(m + 56, &l, 8);
        }

        chunks(m, h);

    } while (read_l == 64);

    if (fclose(fp) == EOF) {
        fprintf(stderr, "fclose fails on f_name \"%s\", exiting...\n", f_name);
        exit(1);
    }

    memcpy(hashed, h, sizeof(h));

    return;
}

/* main */
/* Will simply call sha256, in case we need sha256 latter... */
/* We expect a filename a la `sha256sum` */
int main(int argc, char *argv[]) {
    char *f_name;
    uint32_t h[8];
    size_t i;
    if (!(argc > 1)) {
        fprintf(stderr, "No filename argument provided, exiting...\n");
        exit(1);
    }
    f_name = argv[1];
    hash_f(f_name, h);
    for (i = 0; i < 8; i++) {
        printf("%08x", h[i]);
    }
    printf("  %s\n", f_name);
    return 0;
}
