#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define SHA3_256_HashSize 32
#define SHA3_512_HashSize 64

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

#endif // FIPS202_H
