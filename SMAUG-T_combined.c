

#include <stdio.h>
#include <stdint.h>
#include "parameters.h"
#include "fips202.h"
//#include "randombytes.h"


#include <stddef.h>
#include <stdint.h>

#include <string.h>
#include <stdlib.h>

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64 - offset)))

#define SCHB_N 16

#define N_RES (LWE_N << 1)
#define N_SB (LWE_N >> 2)       // LWE_N : 256 = 2^8 -> 2^6
#define N_SB_RES (2 * N_SB - 1)

#define OVERFLOWING_MUL(X, Y) ((uint16_t)((uint32_t)(X) * (uint32_t)(Y)))

#define KARATSUBA_N 64


#define RAND 0

#include <Windows.h>
#include <wincrypt.h> /* CryptAcquireContext, CryptGenRandom */



#if RAND == 0


static int randombytes(void* buf, const size_t n)
{
    HCRYPTPROV ctx;
    BOOL tmp;

    tmp = CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT);
    if (tmp == FALSE)
    {
        return -1;
    }

    tmp = CryptGenRandom(ctx, (unsigned long)n, (BYTE*)buf);
    if (tmp == FALSE)
    {
        return -1;
    }

    tmp = CryptReleaseContext(ctx, 0);
    if (tmp == FALSE)
    {
        return -1;
    }

    return 0;
}
#elif RAND == 1
void randombytes(uint8_t* buf, int len)
{
    for (int i = 0; i < len; i++)
    {
        *buf = i;
        buf++;
    }
}
#endif


static uint64_t load64(const uint8_t x[8]) {
    unsigned int i;
    uint64_t r = 0;

    for (i = 0; i < 8; i++)
        r |= (uint64_t)x[i] << 8 * i;

    return r;
}

static void store64(uint8_t x[8], uint64_t u) {
    unsigned int i;

    for (i = 0; i < 8; i++)
        x[i] = u >> 8 * i;
}

static void load16_littleendian(int16_t* out, const int outlen,
    const uint8_t* in) {
    int pos = 0;
    for (int i = 0; i < outlen; ++i) {
        out[i] = ((int16_t)(in[pos])) | ((int16_t)(in[pos + 1]) << 8);
        pos += 2;
    }
}

static void store16_littleendian(uint8_t* out, const int16_t* in,
    const int inlen) {
    int pos = 0;
    for (int i = 0; i < inlen; ++i) {
        out[pos] = in[i];
        out[pos + 1] = in[i] >> 8;
        pos += 2;
    }
}

static uint32_t load24_littleendian(const uint8_t x[3]) {
    uint32_t r;
    r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    return r;
}
static uint32_t load32_littleendian(const uint8_t x[4]) {
    uint32_t r;
    r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

static void load64_littleendian(uint64_t* out, const unsigned int outlen,
    const uint8_t* in) {
    unsigned int i, pos = 0;
    for (i = 0; i < outlen; ++i) {
        out[i] =
            ((uint64_t)(in[pos])) | ((uint64_t)(in[pos + 1]) << 8) |
            ((uint64_t)(in[pos + 2]) << 16) | ((uint64_t)(in[pos + 3]) << 24) |
            ((uint64_t)(in[pos + 4]) << 32) | ((uint64_t)(in[pos + 5]) << 40) |
            ((uint64_t)(in[pos + 6]) << 48) | ((uint64_t)(in[pos + 7]) << 56);
        pos += 8;
    }
}


/* Keccak round constants */
const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    (uint64_t)0x0000000000000001ULL, (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL, (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL, (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL, (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL, (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL, (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL, (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL, (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL, (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL, (uint64_t)0x8000000080008008ULL };

static void KeccakF1600_StatePermute(uint64_t state[25]) {
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    // copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < NROUNDS; round += 2) {
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        // thetaRhoPiChiIotaPrepareTheta(round, A, E)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= (uint64_t)KeccakF_RoundConstants[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka, 3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De;
        BCa = ROL(Abe, 1);
        Agi ^= Di;
        BCe = ROL(Agi, 6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu, 8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= (uint64_t)KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    // copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

static void keccak_init(uint64_t s[25]) {
    unsigned int i;
    for (i = 0; i < 25; i++)
        s[i] = 0;
}

static unsigned int keccak_absorb(uint64_t s[25], unsigned int pos,
    unsigned int r, const uint8_t* in,
    size_t inlen) {
    unsigned int i;

    while (pos + inlen >= r) {
        for (i = pos; i < r; i++)
            s[i / 8] ^= (uint64_t)*in++ << 8 * (i % 8);
        inlen -= r - pos;
        KeccakF1600_StatePermute(s);
        pos = 0;
    }

    for (i = pos; i < pos + inlen; i++)
        s[i / 8] ^= (uint64_t)*in++ << 8 * (i % 8);

    return i;
}

static void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r,
    uint8_t p) {
    s[pos / 8] ^= (uint64_t)p << 8 * (pos % 8);
    s[r / 8 - 1] ^= 1ULL << 63;
}

static unsigned int keccak_squeeze(uint8_t* out, size_t outlen, uint64_t s[25],
    unsigned int pos, unsigned int r) {
    
    unsigned int i;

    while (outlen) {
        if (pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
        for (i = pos; i < r && i < pos + outlen; i++)
            *out++ = s[i / 8] >> 8 * (i % 8);
        outlen -= i - pos;
        pos = i;
    }

    return pos;
}

static void keccak_absorb_once(uint64_t s[25], unsigned int r,
    const uint8_t* in, size_t inlen, uint8_t p) {
    unsigned int i;

    for (i = 0; i < 25; i++)
        s[i] = 0;

    while (inlen >= r) {
        for (i = 0; i < r / 8; i++)
            s[i] ^= load64(in + 8 * i);
        in += r;
        inlen -= r;
        KeccakF1600_StatePermute(s);
    }

    for (i = 0; i < inlen; i++)
        s[i / 8] ^= (uint64_t)in[i] << 8 * (i % 8);

    s[i / 8] ^= (uint64_t)p << 8 * (i % 8);
    s[(r - 1) / 8] ^= 1ULL << 63;
}

static void keccak_squeezeblocks(uint8_t* out, size_t nblocks, uint64_t s[25],
    unsigned int r) {
    unsigned int i;

    while (nblocks) {
        KeccakF1600_StatePermute(s);
        for (i = 0; i < r / 8; i++)
            store64(out + 8 * i, s[i]);
        out += r;
        nblocks -= 1;
    }
}

void shake128_init(keccak_state* state) {
    keccak_init(state->s);
    state->pos = 0;
}

void shake128_absorb(keccak_state* state, const uint8_t* in, size_t inlen) {
    state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
}

void shake128_finalize(keccak_state* state) {
    keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
    state->pos = SHAKE128_RATE;
}

void shake128_squeeze(uint8_t* out, size_t outlen, keccak_state* state) {
    state->pos =
        keccak_squeeze(out, outlen, state->s, state->pos, SHAKE128_RATE);
}

void shake128_absorb_once(keccak_state* state, const uint8_t* in,
    size_t inlen) {
    keccak_absorb_once(state->s, SHAKE128_RATE, in, inlen, 0x1F);
    state->pos = SHAKE128_RATE;
}

void shake128_squeezeblocks(uint8_t* out, size_t nblocks, keccak_state* state) {
    keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}

void shake256_init(keccak_state* state) {
    keccak_init(state->s);
    state->pos = 0;
}

void shake256_absorb(keccak_state* state, const uint8_t* in, size_t inlen) {
    state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, in, inlen);
}

void shake256_finalize(keccak_state* state) {
    keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
    state->pos = SHAKE256_RATE;
}

void shake256_squeeze(uint8_t* out, size_t outlen, keccak_state* state) {
    state->pos =
        keccak_squeeze(out, outlen, state->s, state->pos, SHAKE256_RATE);
}

void shake256_absorb_once(keccak_state* state, const uint8_t* in,
    size_t inlen) {
    keccak_absorb_once(state->s, SHAKE256_RATE, in, inlen, 0x1F);
    state->pos = SHAKE256_RATE;
}

void shake256_squeezeblocks(uint8_t* out, size_t nblocks, keccak_state* state) {
    keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
}

void shake128(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    size_t nblocks;
    keccak_state state;

    shake128_absorb_once(&state, in, inlen);
    nblocks = outlen / SHAKE128_RATE;
    shake128_squeezeblocks(out, nblocks, &state);
    outlen -= nblocks * SHAKE128_RATE;
    out += nblocks * SHAKE128_RATE;
    shake128_squeeze(out, outlen, &state);
}

void shake256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    size_t nblocks;
    keccak_state state;

    shake256_absorb_once(&state, in, inlen);
    nblocks = outlen / SHAKE256_RATE;
    shake256_squeezeblocks(out, nblocks, &state);
    outlen -= nblocks * SHAKE256_RATE;
    out += nblocks * SHAKE256_RATE;
    shake256_squeeze(out, outlen, &state);
}

void sha3_256(uint8_t h[32], const uint8_t* in, size_t inlen) {
    unsigned int i;
    uint64_t s[25];

    keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    for (i = 0; i < 4; i++)
        store64(h + 8 * i, s[i]);
}

void sha3_512(uint8_t h[64], const uint8_t* in, size_t inlen) {
    unsigned int i;
    uint64_t s[25];

    keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
    KeccakF1600_StatePermute(s);
    for (i = 0; i < 8; i++)
        store64(h + 8 * i, s[i]);
}




int verify(const uint8_t* a, const uint8_t* b, size_t len) {
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++)
        r |= a[i] ^ b[i];


    return ((-(uint64_t)(r))) >> 63;
}

void cmov(uint8_t* r, const uint8_t* x, size_t len, uint8_t b) {
    size_t i;

    b = -b;
    for (i = 0; i < len; i++)
        r[i] ^= b & (r[i] ^ x[i]);
}




static void karatsuba_simple(const uint16_t* a_1, const uint16_t* b_1,
    uint16_t* result_final) {
    uint16_t d01[KARATSUBA_N / 2 - 1];
    uint16_t d0123[KARATSUBA_N / 2 - 1];
    uint16_t d23[KARATSUBA_N / 2 - 1];
    uint16_t result_d01[KARATSUBA_N - 1];

    int32_t i, j;

    memset(result_d01, 0, (KARATSUBA_N - 1) * sizeof(uint16_t));
    memset(d01, 0, (KARATSUBA_N / 2 - 1) * sizeof(uint16_t));
    memset(d0123, 0, (KARATSUBA_N / 2 - 1) * sizeof(uint16_t));
    memset(d23, 0, (KARATSUBA_N / 2 - 1) * sizeof(uint16_t));
    memset(result_final, 0, (2 * KARATSUBA_N - 1) * sizeof(uint16_t));

    uint16_t acc1, acc2, acc3, acc4, acc5, acc6, acc7, acc8, acc9, acc10;

    for (i = 0; i < KARATSUBA_N / 4; i++) {
        acc1 = a_1[i];                       // a0 = A[ 0 ~ 15]
        acc2 = a_1[i + KARATSUBA_N / 4];     // a1 = A[16 ~ 31]
        acc3 = a_1[i + 2 * KARATSUBA_N / 4]; // a2 = A[32 ~ 47]
        acc4 = a_1[i + 3 * KARATSUBA_N / 4]; // a3 = A[48 ~ 63]

        for (j = 0; j < KARATSUBA_N / 4; j++) {

            acc5 = b_1[j];                   // b0 = B[ 0 ~ 15]
            acc6 = b_1[j + KARATSUBA_N / 4]; // b1 = B[16 ~ 31]

            result_final[i + j + 0 * KARATSUBA_N / 4] =
                result_final[i + j + 0 * KARATSUBA_N / 4] +
                OVERFLOWING_MUL(acc1, acc5);                    // a0 * b0                                  -> result[ 0 ~ 30]  = (a0 * b0)
            result_final[i + j + 2 * KARATSUBA_N / 4] =
                result_final[i + j + 2 * KARATSUBA_N / 4] +
                OVERFLOWING_MUL(acc2, acc6);                    // a1 * b1                                  -> result[32 ~ 62]  = (a1 * b1)

            acc7 = acc5 + acc6; // b01                          // acc7 = b0 + b1
            acc8 = acc1 + acc2; // a01                          // acc8 = a0 + a1
            d01[i + j] = d01[i + j] + (uint16_t)(acc7 * (uint64_t)acc8);    // d01 = (a0 + a1)(b0 + b1)
            //--------------------------------------------------------

            acc7 = b_1[j + 2 * KARATSUBA_N / 4]; // b2          // b2 = B[32 ~ 47]
            acc8 = b_1[j + 3 * KARATSUBA_N / 4]; // b3          // b3 = B[48 ~ 63]
            result_final[i + j + 4 * KARATSUBA_N / 4] =
                result_final[i + j + 4 * KARATSUBA_N / 4] +
                OVERFLOWING_MUL(acc7, acc3);                    // a2 * b2                                  -> result[64 ~ 94]  = (a2 * b2)

            result_final[i + j + 6 * KARATSUBA_N / 4] =
                result_final[i + j + 6 * KARATSUBA_N / 4] +
                OVERFLOWING_MUL(acc8, acc4);                    // a3 * b3                                  -> result[96 ~ 127] = (a3 * b3)

            acc9 = acc3 + acc4;                                 // acc9  = a2 + a3
            acc10 = acc7 + acc8;                                // acc10 = b2 + b3
            d23[i + j] = d23[i + j] + OVERFLOWING_MUL(acc9, acc10);     // d23 = (a2 + a3)(b2 + b3)
            //--------------------------------------------------------

            acc5 = acc5 + acc7; // b02                          // acc5 = b0 + b2
            acc7 = acc1 + acc3; // a02                          // acc7 = a0 + a2
            result_d01[i + j + 0 * KARATSUBA_N / 4] =
                result_d01[i + j + 0 * KARATSUBA_N / 4] +
                OVERFLOWING_MUL(acc5, acc7);                    // (b0 + b2)(a0 + a2)   [ 0 ~ 30]

            acc6 = acc6 + acc8; // b13                          // acc6 = b1 + b3
            acc8 = acc2 + acc4;                                 // acc8 = a1 + a3
            result_d01[i + j + 2 * KARATSUBA_N / 4] =
                result_d01[i + j + 2 * KARATSUBA_N / 4] +
                OVERFLOWING_MUL(acc6, acc8);                    // (b1 + b3)(a1 + a3)   [32 ~ 62]

            acc5 = acc5 + acc6;                                 // acc5 = b0 + b1 + b2 + b3
            acc7 = acc7 + acc8;                                 // acc7 = a0 + a1 + a2 + a3
            d0123[i + j] = d0123[i + j] + OVERFLOWING_MUL(acc5, acc7);  // d0123 = (a0 + a1 + a2 + a3)(b0 + b1 + b2 + b3)
        }
    }

    // 2nd last stage

    for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
        d0123[i] = d0123[i] - result_d01[i + 0 * KARATSUBA_N / 4] -     // d0123 = (a0 + a1 + a2 + a3)(b0 + b1 + b2 + b3) - (b0 + b2)(a0 + a2) - (b1 + b3)(a1 + a3)
            result_d01[i + 2 * KARATSUBA_N / 4];
        d01[i] = d01[i] - result_final[i + 0 * KARATSUBA_N / 4] -       // d01[ 0 ~ 30]   = (a0 + a1)(b0 + b1) - a0 * b0 - a1 * b1 
            result_final[i + 2 * KARATSUBA_N / 4];
        d23[i] = d23[i] - result_final[i + 4 * KARATSUBA_N / 4] -       // d23[ 0 ~ 30]   = (a2 + a3)(b2 + b3) - a2 * b2 - a3 * b3
            result_final[i + 6 * KARATSUBA_N / 4];
    }

    for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
        result_d01[i + 1 * KARATSUBA_N / 4] =                           // result_d01[16 ~ 30] = (a0 + a2)(b0 + b2)[16 ~ 30] + {(a0 + a1 + a2 + a3)(b0 + b1 + b2 + b3) - (b0 + b2)(a0 + a2) - (b1 + b3)(a1 + a3)}[0 ~ 14]
            result_d01[i + 1 * KARATSUBA_N / 4] + d0123[i];             // result_d01[31 ~ 46] = {(a0 + a1 + a2 + a3)(b0 + b1 + b2 + b3) - (b0 + b2)(a0 + a2) - (b1 + b3)(a1 + a3)}[15 ~ 30]

        result_final[i + 1 * KARATSUBA_N / 4] =                         // result[16 ~ 30]     = a0 * b0[16 ~ 30] + {(a0 + a1)(b0 + b1) - a0 * b0 - a1 * b1}[ 0 ~ 14]
            result_final[i + 1 * KARATSUBA_N / 4] + d01[i];             // result[31]          = {(a0 + a1)(b0 + b1) - a0 * b0 - a1 * b1}[15]
        // result[32 ~ 46]     = a1 * b1[ 0 ~ 14] + {(a0 + a1)(b0 + b1) - a0 * b0 - a1 * b1}[16 ~ 30]

        result_final[i + 5 * KARATSUBA_N / 4] =                         // result[80 ~ 94]     = a2 * b2[16 ~ 30] + {(a2 + a3)(b2 + b3) - a2 * b2 - a3 * b3}[ 0 ~ 14]
            result_final[i + 5 * KARATSUBA_N / 4] + d23[i];             // result[95]          = {(a2 + a3)(b2 + b3) - a2 * b2 - a3 * b3}[15]
        // result[96 ~ 110]    = a3 * b3[ 0 ~ 14] + {(a2 + a3)(b2 + b3) - a2 * b2 - a3 * b3}[16 ~ 30]
    }

    // Last stage
    for (i = 0; i < KARATSUBA_N - 1; i++) {
        result_d01[i] =
            result_d01[i] - result_final[i] - result_final[i + KARATSUBA_N];    // result_d01[ 0 ~ 62] = (A1 + A0)(B1 + B0) - A1B1 - A0B0
    }

    for (i = 0; i < KARATSUBA_N - 1; i++) {
        result_final[i + 1 * KARATSUBA_N / 2] =
            result_final[i + 1 * KARATSUBA_N / 2] + result_d01[i];              // result[32 ~ 62] += result_d01[ 0 ~ 30]
    }                                                                           // result[63]      += result_d01[31]
                                                                                // result[64 ~ 94] += result_d01[32 ~ 62]
}

static void toom_cook_4way(const uint16_t* a1, const uint16_t* b1,
    uint16_t* result) {
    uint16_t inv3 = 43691, inv9 = 36409, inv15 = 61167;

    uint16_t aw1[N_SB], aw2[N_SB], aw3[N_SB], aw4[N_SB], aw5[N_SB], aw6[N_SB],
        aw7[N_SB];  // 2^6, 즉, 256차 -> 64차 7개로 쪼갠다는 의미임
    uint16_t bw1[N_SB], bw2[N_SB], bw3[N_SB], bw4[N_SB], bw5[N_SB], bw6[N_SB],
        bw7[N_SB];  // 곱할 수인 b부분 역시 64차 7개로 쪼개줌
    uint16_t w1[N_SB_RES] = { 0 }, w2[N_SB_RES] = { 0 }, w3[N_SB_RES] = { 0 },
        w4[N_SB_RES] = { 0 }, w5[N_SB_RES] = { 0 }, w6[N_SB_RES] = { 0 },
        w7[N_SB_RES] = { 0 };
    uint16_t r0, r1, r2, r3, r4, r5, r6, r7;
    uint16_t* A0, * A1, * A2, * A3, * B0, * B1, * B2, * B3;

    /*
        a1의 경우

    */
    A0 = (uint16_t*)a1;            // A0 = a1[0   ~  63]
    A1 = (uint16_t*)&a1[N_SB];     // A1 = a1[64  ~ 127]
    A2 = (uint16_t*)&a1[2 * N_SB]; // A2 = a1[128 ~ 191]
    A3 = (uint16_t*)&a1[3 * N_SB]; // A3 = a1[192 ~ 255]
    B0 = (uint16_t*)b1;
    B1 = (uint16_t*)&b1[N_SB];
    B2 = (uint16_t*)&b1[2 * N_SB];
    B3 = (uint16_t*)&b1[3 * N_SB];

    uint16_t* C;
    C = result;

    int i, j;

    // EVALUATION   평가 지점은 infty, 2, 1, -1, 1/2, -1/2, 0
    for (j = 0; j < N_SB; ++j) {
        r0 = A0[j];     // r0 = a1[i]
        r1 = A1[j];     // r1 = a1[i + 64]
        r2 = A2[j];     // r2 = a1[i + 128]
        r3 = A3[j];     // r3 = a1[i + 192]
        r4 = r0 + r2;   // r4 = a1[i] + a1[i + 128]
        r5 = r1 + r3;   // r5 = a1[i + 64] + a1[i + 192]
        r6 = r4 + r5;   // r6 = a1[i] + a1[i + 64] + a1[i + 128] + a1[i + 192]
        r7 = r4 - r5;   // r7 = a1[i] + a1[i + 128] - a1[i + 64] + a1[i + 192]
        aw3[j] = r6;    // aw3 = a1[i] + a1[i + 64] + a1[i + 128] + a1[i + 192] -> 평가 지점 A( 1)
        aw4[j] = r7;    // aw4 = a1[i] - a1[i + 64] + a1[i + 128] + a1[i + 192] -> 평가 지점 A(-1)

        r4 = ((r0 << 2) + r2) << 1; // r4 = 8 * a1[i]                  + 2 * a1[i + 128] 
        r5 = (r1 << 2) + r3;        // r5 =             4 * a1[i + 64]                   + a1[i + 192] 
        r6 = r4 + r5;   // r6 = 8 * a1[i] + 4 * a1[i + 64] + 2 * a1[i + 128] + a1[i + 192]
        r7 = r4 - r5;   // r7 = 8 * a1[i] - 4 * a1[i + 64] + 2 * a1[i + 128] - a1[i + 192]
        aw5[j] = r6;    // aw5 = 8 * a1[i] + 4 * a1[i + 64] + 2 * a1[i + 128] + a1[i + 192] -> 평가 지점 8 * A( 1/2)
        aw6[j] = r7;    // aw6 = 8 * a1[i] - 4 * a1[i + 64] + 2 * a1[i + 128] - a1[i + 192] -> 평가 지점 8 * A(-1/2)
        r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;    // r4 = a1[i] + 2 * a1[i + 64] + 4 * a1[i + 128] + 8 * a1[i + 192]
        aw2[j] = r4;    // aw2 = a1[i] + 2 * a1[i + 64] + 4 * a1[i + 128] + 8 * a1[i + 192] -> 평가 지점 A(2)
        aw7[j] = r0;    // aw7 = a1[i]       -> 평가 지점 A(0)
        aw1[j] = r3;    // aw1 = a1[i + 192] -> 평가 지점 A(infty)
    }
    for (j = 0; j < N_SB; ++j) {
        r0 = B0[j];
        r1 = B1[j];
        r2 = B2[j];
        r3 = B3[j];
        r4 = r0 + r2;
        r5 = r1 + r3;
        r6 = r4 + r5;
        r7 = r4 - r5;
        bw3[j] = r6;
        bw4[j] = r7;
        r4 = ((r0 << 2) + r2) << 1;
        r5 = (r1 << 2) + r3;
        r6 = r4 + r5;
        r7 = r4 - r5;
        bw5[j] = r6;
        bw6[j] = r7;
        r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
        bw2[j] = r4;
        bw7[j] = r0;
        bw1[j] = r3;
    } // B 역시 마찬가지로 평가 지점은 infty, 2, 1, -1, 1/2, -1/2, 0

    // MULTIPLICATION
    karatsuba_simple(aw1, bw1, w1); // A(infty) * B(infty)  = w1 (64차 끼리의 곱셈을 진행하는데, 2-level Karatsuba이기 때문에, 내부에서 4개로 변경하여 연산을 진행한다.)
    karatsuba_simple(aw2, bw2, w2); // A(2)     * B(2)      = w2
    karatsuba_simple(aw3, bw3, w3); // A(1)     * B(1)      = w3
    karatsuba_simple(aw4, bw4, w4); // A(-1)    * B(-1)     = w4
    karatsuba_simple(aw5, bw5, w5); // A(1/2)   * B(1/2)    = w5
    karatsuba_simple(aw6, bw6, w6); // A(-1/2)  * B(-1/2)   = w6
    karatsuba_simple(aw7, bw7, w7); // A(0)     * B(0)      = w7

    // 각 값에 대해 2-level karatsuba 연산을 이용해서 평가 값을 계산

    // INTERPOLATION
/* 보간 행렬.

c0 =    r6 =       0	    0	   0	    0	    0	    0	   1           r0 (infty)
c1 =    r5 =    -1/2	 1/90	-1/3	  1/9	 1/36	-1/60	-1/2           r1 (2)
c2 =    r4 =     1/4	    0	-1/6	 -1/6	 1/24	 1/24	  -5           r2 (1)
c3 =    r3 =     5/2	-1/18	 3/2	-7/18	-1/18	    0	 5/2           r3 (-1)
c4 =    r2 =    -5/4	    0	 2/3	  2/3	-1/24	-1/24	   4           r4 (1/2)
c5 =    r1 =      -2	 2/45	-2/3	 -2/9	 1/36	 1/60	  -2           r5 (-1/2)
c6 =    r0 =       1	    0	   0	    0	    0	    0	   0           r6 (0)

*/
    for (i = 0; i < N_SB_RES; ++i) {
        r0 = w1[i];
        r1 = w2[i];
        r2 = w3[i];
        r3 = w4[i];
        r4 = w5[i];
        r5 = w6[i];
        r6 = w7[i];

        r1 = r1 + r4;               // r1 = r(1) + r(4)
        r5 = r5 - r4;               // r5 = r(5) - r(4)
        r3 = ((r3 - r2) >> 1);      // r3 = (r(3) - r(2)) / 2
        r4 = r4 - r0;               // r4 = r(4) - r(0)
        r4 = r4 - (r6 << 6);        // r4 = r(4) - r(0) - 64 * r(6)
        r4 = (r4 << 1) + r5;        // r4 = 2 * (r(4) - r(0) - 64 * r(6)) + r(5) - r(4)
        r2 = r2 + r3;               // r2 = r(2) + (r(3) - r(2)) / 2
        r1 = r1 - (r2 << 6) - r2;   // r1 = r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2
        r2 = r2 - r6;               // r2 = r(2) + (r(3) - r(2)) / 2 - r(6)
        r2 = r2 - r0;               // r2 = r(2) + (r(3) - r(2)) / 2 - r(6) - r(0)
        r1 = r1 + 45 * r2;          // r1 = r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0))
        r4 = (uint16_t)(((r4 - (r2 << 3)) * (uint32_t)inv3) >> 3);  // r4 = {2 * (r(4) - r(0) - 64 * r(6)) + r(5) - r(4) - 8 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0))} * 1/24
        r5 = r5 + r1;                                               // r5 = r(5) + r(4) + r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0))
        r1 = (uint16_t)(((r1 + (r3 << 4)) * (uint32_t)inv9) >> 1);  // r1 = {r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0)) + 8 * ((r(3) - r(2)))} * 1/18
        r3 = -(r3 + r1);                                            // r3 = - {(r(3) - r(2)) / 2} - {r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0)) + 8 * ((r(3) - r(2)))} * 1/18
        r5 = (uint16_t)(((30 * r1 - r5) * (uint32_t)inv15) >> 2);   // r5 = {30 * ({r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0)) + 8 * ((r(3) - r(2)))} * 1/18) - r(5) + r(4) + r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0))} * 1/60
        r2 = r2 - r4;               // r2 = r(2) + (r(3) - r(2)) / 2 - r(6) - r(0) - {{2 * (r(4) - r(0) - 64 * r(6)) + r(5) + r(4) - 8 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0))} * 1/24}
        r1 = r1 - r5;               // r1 = {r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0)) + 8 * ((r(3) - r(2)))} * 1/18 - {{30 * ({r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0)) + 8 * ((r(3) - r(2)))} * 1/18) - r(5) + r(4) + r(1) + r(4) - 64 * (r(2) + (r(3) - r(2)) / 2) - r(2) + (r(3) - r(2)) / 2 + 45 * (r(2) + (r(3) - r(2)) / 2 - r(6) - r(0))} * 1/60}

        C[i] += r6;         // C[  0 ~ 126]
        C[i + 64] += r5;    // C[ 64 ~ 190]
        C[i + 128] += r4;   // C[128 ~ 254]
        C[i + 192] += r3;   // C[192 ~ 318]
        C[i + 256] += r2;   // C[256 ~ 382]
        C[i + 320] += r1;   // C[320 ~ 446]
        C[i + 384] += r0;   // C[384 ~ 510]
    }
}

/* res += a*b */
void poly_mul_acc(const int16_t a[LWE_N], const int16_t b[LWE_N],
    int16_t res[LWE_N]) {
    uint16_t c[2 * LWE_N] = { 0 };
    int i;

    toom_cook_4way((uint16_t*)a, (uint16_t*)b, c);

    /* reduction */
    for (i = LWE_N; i < 2 * LWE_N; i++) {           // SMAUG-T을 Quotient 하는 irred_poly 는 x^256 + 1 이기 때문에
        res[i - LWE_N] += (c[i - LWE_N] - c[i]);    // c[0~510]에서 c[256 ~ 510] -> -c[0 ~ 254] 이므로
    }                                               // res[0~255] = c[0 ~ 255] - c[256 ~ 510] 으로 reduction 을 진행
}

void poly_add(poly* r, const poly* a, const poly* b) {
    unsigned int i;
    for (i = 0; i < LWE_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly* r, const poly* a, const poly* b) {
    unsigned int i;
    for (i = 0; i < LWE_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

void vec_vec_mult(poly* r, const polyvec* a, const polyvec* b) {
    unsigned int i;
    for (i = 0; i < MODULE_RANK; i++)
        poly_mul_acc(a->vec[i].coeffs, b->vec[i].coeffs, r->coeffs);
}

void vec_vec_mult_add(poly* r, const polyvec* a, const polyvec* b,
    const uint8_t mod) {
    unsigned int i, j;
    polyvec al;
    poly res;

    for (i = 0; i < MODULE_RANK; ++i)
        for (j = 0; j < LWE_N; ++j)
            al.vec[i].coeffs[j] = a->vec[i].coeffs[j] >> mod;

    memset(&res, 0, sizeof(poly));
    vec_vec_mult(&res, &al, b);
    for (j = 0; j < LWE_N; ++j)
        res.coeffs[j] <<= mod;

    poly_add(r, r, &res);
}

void matrix_vec_mult_add(polyvec* r, const polyvec a[MODULE_RANK],
    const polyvec* b) {
    unsigned int i, j, k;
    polyvec at;

    for (i = 0; i < MODULE_RANK; ++i) {
        for (j = 0; j < MODULE_RANK; ++j)
            for (k = 0; k < LWE_N; ++k)
                at.vec[j].coeffs[k] = a[j].vec[i].coeffs[k] >> _16_LOG_Q;

        vec_vec_mult(&r->vec[i], &at, b);
        for (j = 0; j < LWE_N; ++j)
            r->vec[i].coeffs[j] <<= _16_LOG_Q;
    }
}

void matrix_vec_mult_sub(polyvec* r, const polyvec a[MODULE_RANK],
    const polyvec* b) {
    unsigned int i, j, k;
    polyvec al;
    poly res;

    for (i = 0; i < MODULE_RANK; ++i) {
        for (j = 0; j < MODULE_RANK; ++j)
            for (k = 0; k < LWE_N; ++k)
                al.vec[j].coeffs[k] = a[i].vec[j].coeffs[k] >> _16_LOG_Q;   // A 행렬 mod q(2^10)

        memset(&res, 0, sizeof(poly));
        vec_vec_mult(&res, &al, b);             // A * s
        for (j = 0; j < LWE_N; ++j)
            res.coeffs[j] <<= _16_LOG_Q;        // e값을 side channel을 막기 위해 <<6 을 진행했기 때문에 A*s 역시 마찬가지로 진행

        poly_sub(&r->vec[i], &r->vec[i], &res); // e - A*s 즉 b = -As + e 의 값을 얻어줌
    }
}




void Rq_to_bytes(uint8_t bytes[PKPOLY_BYTES], const poly* data) {
    int16_t tmp[LWE_N] = { 0 };
    int b_idx = 0, d_idx = 0;
    unsigned int i, j;

#if LOG_Q == 10
    for (i = 0; i < LWE_N; ++i) {
        bytes[i] = data->coeffs[i] >> 8;        // bytes[i]에 b값의 상위 8bit를 저장
        tmp[i] = data->coeffs[i] & 0x00c0;      // tmp[i]에 b값의 중위 2bit를 저장    -> 실제로 필요한 값인 10bit만을 저장한다는 의미임
    }
    int16_t buf[DATA_OFFSET * 2] = { 0 };
    for (i = 0; i < 2; ++i) {
        for (j = 0; j < DATA_OFFSET; ++j) {
            buf[b_idx + j]  = tmp[d_idx + j]                   << 8;  // buf[0~15 + 8*b_idx] = tmp[0  ~ 15 + 128*b_idx] 1100 0000 0000 0000 
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET + j]     << 6;  // buf[0~15 + 8*b_idx] = tmp[16 ~ 31 + 128*b_idx] 0011 0000 0000 0000
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 2 + j] << 4;  // buf[0~15 + 8*b_idx] = tmp[32 ~ 47 + 128*b_idx] 0000 1100 0000 0000
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 3 + j] << 2;  // buf[0~15 + 8*b_idx] = tmp[48 ~ 63 + 128*b_idx] 0000 0011 0000 0000
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 4 + j];       // buf[0~15 + 8*b_idx] = tmp[64 ~ 79 + 128*b_idx] 0000 0000 1100 0000 
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 5 + j] >> 2;  // buf[0~15 + 8*b_idx] = tmp[80 ~ 95 + 128*b_idx] 0000 0000 0011 0000
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 6 + j] >> 4;  // buf[0~15 + 8*b_idx] = tmp[96 ~111 + 128*b_idx] 0000 0000 0000 1100
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 7 + j] >> 6;  // buf[0~15 + 8*b_idx] = tmp[112~127 + 128*b_idx] 0000 0000 0000 0011
        }                                                             // 위와 같이 값을 저장
        b_idx += DATA_OFFSET;
        d_idx += DATA_OFFSET * 8;
    }
    store16_littleendian(bytes + LWE_N, buf, DATA_OFFSET * 2);        // 저장한 값을 byte 형식으로 bytes[256~319] 에 저장
#endif
#if LOG_Q == 11
    for (i = 0; i < LWE_N; ++i) {
        bytes[i] = data->coeffs[i] >> 8;
        tmp[i] = data->coeffs[i] & 0x00e0;
    }
    int shift = 5;
    int16_t buf[DATA_OFFSET * 3] = { 0 };
    for (i = 0; i < 3; ++i) {
        for (j = 0; j < DATA_OFFSET; ++j) {
            buf[b_idx + j] = (tmp[j] >> shift) & 0x01;
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET + j] << 8;
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 2 + j] << 5;
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 3 + j] << 2;
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 4 + j] >> 1;
            buf[b_idx + j] |= tmp[d_idx + DATA_OFFSET * 5 + j] >> 4;
        }
        b_idx += DATA_OFFSET;
        d_idx += DATA_OFFSET * 5;
        shift++;
    }
    store16_littleendian(bytes + LWE_N, buf, DATA_OFFSET * 3);
#endif
}

void bytes_to_Rq(poly* data, const uint8_t bytes[PKPOLY_BYTES]) {
    int16_t tmp[LWE_N] = { 0 };
    int b_idx = 0, d_idx = 0;
    unsigned int i, j;

#if LOG_Q == 10
    for (i = 0; i < LWE_N; ++i)
        data->coeffs[i] = (int16_t)bytes[i] << 8;               // data->coeffs[i]의 상위 8bit를 shake128의 결과값으로 집어 넣어 줌

    int16_t buf[DATA_OFFSET * 2] = { 0 };
    load16_littleendian(buf, DATA_OFFSET * 2, bytes + LWE_N);   // buf 배열에 들어가지 않은 나머지 bytes 값을 저장
    // 320 - 256 = 64 즉, buf[i] = bytes[2i+1] | bytes[2i] 으로 저장해줌

    for (i = 0; i < 2; ++i) {
        for (j = 0; j < DATA_OFFSET; ++j) {
            tmp[d_idx + j]                   = buf[b_idx + j] >> 8; // temp[0  ~ 15 + 128*d_i] = buf[0~15 + 16*b_i] >> 8; temp에 buf의 상위 8bit를 저장
            tmp[d_idx + DATA_OFFSET + j]     = buf[b_idx + j] >> 6; // temp[16 ~ 31 + 128*d_i] = buf[0~15 + 16*b_i] >> 6; temp에 buf의 상위 10bit를 저장
            tmp[d_idx + DATA_OFFSET * 2 + j] = buf[b_idx + j] >> 4; // temp[32 ~ 47 + 128*d_i] = buf[0~15 + 16*b_i] >> 4; temp에 buf의 상위 12bit를 저장
            tmp[d_idx + DATA_OFFSET * 3 + j] = buf[b_idx + j] >> 2; // temp[48 ~ 63 + 128*d_i] = buf[0~15 + 16*b_i] >> 2; temp에 buf의 상위 14bit를 저장
            tmp[d_idx + DATA_OFFSET * 4 + j] = buf[b_idx + j];      // temp[64 ~ 79 + 128*d_i] = buf[0~15 + 16*b_i];      temp에 buf를 저장
            tmp[d_idx + DATA_OFFSET * 5 + j] = buf[b_idx + j] << 2; // temp[80 ~ 95 + 128*d_i] = buf[0~15 + 16*b_i] << 2; temp에 buf의 하위 14bit | 00 으로 저장
            tmp[d_idx + DATA_OFFSET * 6 + j] = buf[b_idx + j] << 4; // temp[96 ~111 + 128*d_i] = buf[0~15 + 16*b_i] << 4; temp에 buf의 하위 12bit | 0000 으로 저장
            tmp[d_idx + DATA_OFFSET * 7 + j] = buf[b_idx + j] << 6; // temp[112~127 + 128*d_i] = buf[0~15 + 16*b_i] << 6; temp에 buf의 하위 10bit | 000000으로 저장
        }
        b_idx += DATA_OFFSET;
        d_idx += DATA_OFFSET * 8;
    }
    for (i = 0; i < LWE_N; ++i)
        data->coeffs[i] |= tmp[i] & 0x00c0; // coeff[i] = coeff[i] | (temp[i] & 0b 0000 0000 1100 0000)
    // 즉, coeff[i] | temp[i]의 7, 6번 bit를 coeff의 7, 6번 bit로 사용하겠다는 의미
    // -> 앞에서 data->coeffs[i]의 값은 상위 8bit만을 뽑아서 사용했음,
    // 여기에서, >> 6을 통해 각 계수의 값을 상위 10bit만을 사용할 것이기 때문에 마지막 2bit를 temp를 통해 채우겠다는 의미임
#endif
#if LOG_Q == 11
    for (i = 0; i < LWE_N; ++i)
        data->coeffs[i] = (int16_t)bytes[i] << 8;

    int16_t buf[DATA_OFFSET * 3] = { 0 };
    load16_littleendian(buf, DATA_OFFSET * 3, bytes + LWE_N);

    int shift = 5;
    for (i = 0; i < 3; ++i) {
        for (j = 0; j < DATA_OFFSET; ++j) {
            tmp[j] |= (buf[b_idx + j] & 0x01) << shift;
            tmp[d_idx + DATA_OFFSET + j] = buf[b_idx + j] >> 8;
            tmp[d_idx + DATA_OFFSET * 2 + j] = buf[b_idx + j] >> 5;
            tmp[d_idx + DATA_OFFSET * 3 + j] = buf[b_idx + j] >> 2;
            tmp[d_idx + DATA_OFFSET * 4 + j] = buf[b_idx + j] << 1;
            tmp[d_idx + DATA_OFFSET * 5 + j] = buf[b_idx + j] << 4;
        }
        b_idx += DATA_OFFSET;
        d_idx += DATA_OFFSET * 5;
        shift++;
    }
    for (i = 0; i < LWE_N; ++i)
        data->coeffs[i] |= tmp[i] & 0x00e0;
#endif
}

void Rq_vec_to_bytes(uint8_t bytes[PKPOLYVEC_BYTES], const polyvec* data) {
    unsigned int i;
    for (i = 0; i < MODULE_RANK; ++i)
        Rq_to_bytes(bytes + i * PKPOLY_BYTES, &(data->vec[i])); // b vector는 10bit 표현이기 때문에 10 * 256 / 8 = 320 byte로 하나의 b module을 저장할 수 있음
}

void bytes_to_Rq_vec(polyvec* data, const uint8_t bytes[PKPOLYVEC_BYTES]) {
    unsigned int i;
    for (i = 0; i < MODULE_RANK; ++i)
        bytes_to_Rq(&(data->vec[i]), bytes + i * PKPOLY_BYTES);
}

void Rq_mat_to_bytes(uint8_t bytes[PKPOLYMAT_BYTES],
    const polyvec data[MODULE_RANK]) {
    unsigned int i;
    for (i = 0; i < MODULE_RANK; ++i)
        Rq_vec_to_bytes(bytes + i * PKPOLYVEC_BYTES, &(data[i]));
}

void bytes_to_Rq_mat(polyvec data[MODULE_RANK],
    const uint8_t bytes[PKPOLYMAT_BYTES]) {
    unsigned int i;
    for (i = 0; i < MODULE_RANK; ++i)
        bytes_to_Rq_vec(&(data[i]), bytes + i * PKPOLYVEC_BYTES);
}

void Rp_to_bytes(uint8_t bytes[CTPOLY1_BYTES], const poly* data) {
#if LOG_P == 8
    unsigned int i;
    memset(bytes, 0, sizeof(uint8_t) * CTPOLY1_BYTES);
    for (i = 0; i < LWE_N; ++i)
        memcpy(&(bytes[i]), &(data->coeffs[i]), sizeof(uint8_t));
#endif
#if LOG_P == 9
    int16_t tmp[LWE_N] = { 0 };

    unsigned int i;
    for (i = 0; i < LWE_N; ++i) {
        bytes[i] = data->coeffs[i] & 0xff;
        tmp[i] = data->coeffs[i] & 0x00100;
    }

    int16_t buf[DATA_OFFSET] = { 0 };
    for (i = 0; i < DATA_OFFSET; ++i) {
        buf[i] = tmp[i] << 7;
        buf[i] |= tmp[DATA_OFFSET + i] << 6;
        buf[i] |= tmp[DATA_OFFSET * 2 + i] << 5;
        buf[i] |= tmp[DATA_OFFSET * 3 + i] << 4;
        buf[i] |= tmp[DATA_OFFSET * 4 + i] << 3;
        buf[i] |= tmp[DATA_OFFSET * 5 + i] << 2;
        buf[i] |= tmp[DATA_OFFSET * 6 + i] << 1;
        buf[i] |= tmp[DATA_OFFSET * 7 + i];
        buf[i] |= tmp[DATA_OFFSET * 8 + i] >> 1;
        buf[i] |= tmp[DATA_OFFSET * 9 + i] >> 2;
        buf[i] |= tmp[DATA_OFFSET * 10 + i] >> 3;
        buf[i] |= tmp[DATA_OFFSET * 11 + i] >> 4;
        buf[i] |= tmp[DATA_OFFSET * 12 + i] >> 5;
        buf[i] |= tmp[DATA_OFFSET * 13 + i] >> 6;
        buf[i] |= tmp[DATA_OFFSET * 14 + i] >> 7;
        buf[i] |= tmp[DATA_OFFSET * 15 + i] >> 8;
    }
    store16_littleendian(bytes + LWE_N, buf, DATA_OFFSET);
#endif
}

void Rp2_to_bytes(uint8_t bytes[CTPOLY2_BYTES], const poly* data) {
    memset(bytes, 0, sizeof(uint8_t) * CTPOLY2_BYTES);
#if LOG_P2 == 5
    unsigned int i;
    int b_idx = 0;
    int d_idx = 0;
    for (i = 0; i < LWE_N / 8; ++i) {
        b_idx = 5 * i;
        d_idx = 8 * i;

        bytes[b_idx] = (data->coeffs[d_idx] & 0x1f) |
            ((data->coeffs[d_idx + 1] & 0x7) << 5);
        bytes[b_idx + 1] = (data->coeffs[d_idx + 1] & 0x18) >> 3 |
            ((data->coeffs[d_idx + 2] & 0x1f) << 2) |
            ((data->coeffs[d_idx + 3] & 0x01) << 7);
        bytes[b_idx + 2] = ((data->coeffs[d_idx + 3] & 0x1e) >> 1) |
            ((data->coeffs[d_idx + 4] & 0xf) << 4);
        bytes[b_idx + 3] = ((data->coeffs[d_idx + 4] & 0x10) >> 4) |
            ((data->coeffs[d_idx + 5] & 0x1f) << 1) |
            ((data->coeffs[d_idx + 6] & 0x3) << 6);
        bytes[b_idx + 4] = ((data->coeffs[d_idx + 6] & 0x1c) >> 2) |
            ((data->coeffs[d_idx + 7] & 0x1f) << 3);
    }
#endif
#if LOG_P2 == 4
    unsigned int i;
    for (i = 0; i < LWE_N / 2; ++i) {
        bytes[i] = data->coeffs[2 * i] & 0x000f;
        bytes[i] |= (data->coeffs[2 * i + 1] << 4) & 0x00f0;
    }
#endif
#if LOG_P2 == 7
    int d_idx = CTPOLY2_BYTES;
    unsigned int i, j;

    int shift[7] = { 1, 2, 3, 4, 5, 6, 7 };
    int16_t buf[DATA_OFFSET * 7] = { 0 };
    for (i = 0; i < 2; ++i) {
        for (j = 0; j < DATA_OFFSET; ++j) {
            buf[j] |= (data->coeffs[d_idx + j] & 0x40) << shift[0];
            buf[DATA_OFFSET + j] |= (data->coeffs[d_idx + j] & 0x20)
                << shift[1];
            buf[DATA_OFFSET * 2 + j] |= (data->coeffs[d_idx + j] & 0x10)
                << shift[2];
            buf[DATA_OFFSET * 3 + j] |= (data->coeffs[d_idx + j] & 0x08)
                << shift[3];
            buf[DATA_OFFSET * 4 + j] |= (data->coeffs[d_idx + j] & 0x04)
                << shift[4];
            buf[DATA_OFFSET * 5 + j] |= (data->coeffs[d_idx + j] & 0x02)
                << shift[5];
            buf[DATA_OFFSET * 6 + j] |= (data->coeffs[d_idx + j] & 0x01)
                << shift[6];
        }
        d_idx += DATA_OFFSET;
        for (j = 0; j < 7; ++j)
            shift[j] += 8;
    }

    uint8_t tmp[CTPOLY2_BYTES] = { 0 };
    store16_littleendian(tmp, buf, DATA_OFFSET * 7);
    for (i = 0; i < CTPOLY2_BYTES; ++i)
        bytes[i] = tmp[i] | (data->coeffs[i] & 0x7f);
#endif
}

void bytes_to_Rp(poly* data, const uint8_t bytes[CTPOLY1_BYTES]) {
#if LOG_P == 8
    unsigned int i;
    memset(data, 0, sizeof(poly));
    for (i = 0; i < LWE_N; ++i)
        memcpy(&(data->coeffs[i]), &(bytes[i]), sizeof(uint8_t));
#endif
#if LOG_P == 9
    int16_t tmp[LWE_N] = { 0 };
    unsigned int i;
    for (i = 0; i < LWE_N; ++i)
        data->coeffs[i] = (int16_t)bytes[i];

    int16_t buf[DATA_OFFSET] = { 0 };
    load16_littleendian(buf, DATA_OFFSET, bytes + LWE_N);

    for (i = 0; i < DATA_OFFSET; ++i) {
        tmp[i] = buf[i] >> 7;
        tmp[DATA_OFFSET + i] = buf[i] >> 6;
        tmp[DATA_OFFSET * 2 + i] = buf[i] >> 5;
        tmp[DATA_OFFSET * 3 + i] = buf[i] >> 4;
        tmp[DATA_OFFSET * 4 + i] = buf[i] >> 3;
        tmp[DATA_OFFSET * 5 + i] = buf[i] >> 2;
        tmp[DATA_OFFSET * 6 + i] = buf[i] >> 1;
        tmp[DATA_OFFSET * 7 + i] = buf[i];
        tmp[DATA_OFFSET * 8 + i] = buf[i] << 1;
        tmp[DATA_OFFSET * 9 + i] = buf[i] << 2;
        tmp[DATA_OFFSET * 10 + i] = buf[i] << 3;
        tmp[DATA_OFFSET * 11 + i] = buf[i] << 4;
        tmp[DATA_OFFSET * 12 + i] = buf[i] << 5;
        tmp[DATA_OFFSET * 13 + i] = buf[i] << 6;
        tmp[DATA_OFFSET * 14 + i] = buf[i] << 7;
        tmp[DATA_OFFSET * 15 + i] = buf[i] << 8;
    }
    for (i = 0; i < LWE_N; ++i)
        data->coeffs[i] |= tmp[i] & 0x00100;
#endif
}

void bytes_to_Rp2(poly* data, const uint8_t bytes[CTPOLY2_BYTES]) {
    memset(data, 0, sizeof(int16_t) * LWE_N);
#if LOG_P2 == 5
    unsigned int i;
    int b_idx = 0;
    int d_idx = 0;
    for (i = 0; i < LWE_N / 8; ++i) {
        b_idx = 5 * i;
        d_idx = 8 * i;

        data->coeffs[d_idx] = bytes[b_idx] & 0x1f;
        data->coeffs[d_idx + 1] =
            ((bytes[b_idx] & 0xe0) >> 5) | ((bytes[b_idx + 1] & 0x3) << 3);
        data->coeffs[d_idx + 2] = ((bytes[b_idx + 1] & 0x7c) >> 2);
        data->coeffs[d_idx + 3] =
            ((bytes[b_idx + 1] & 0x80) >> 7) | ((bytes[b_idx + 2] & 0xf) << 1);
        data->coeffs[d_idx + 4] =
            ((bytes[b_idx + 2] & 0xf0) >> 4) | ((bytes[b_idx + 3] & 0x1) << 4);
        data->coeffs[d_idx + 5] = ((bytes[b_idx + 3] & 0x3e) >> 1);
        data->coeffs[d_idx + 6] =
            ((bytes[b_idx + 3] & 0xc0) >> 6) | ((bytes[b_idx + 4] & 0x7) << 2);
        data->coeffs[d_idx + 7] = (bytes[b_idx + 4] & 0xf8) >> 3;
    }
#endif
#if LOG_P2 == 4
    unsigned int i;
    for (i = 0; i < LWE_N / 2; ++i) {
        data->coeffs[2 * i] = bytes[i] & 0x0f;
        data->coeffs[2 * i + 1] = (bytes[i] & 0xf0) >> 4;
    }
#endif
#if LOG_P2 == 7
    int d_idx = CTPOLY2_BYTES;
    unsigned int i, j;
    for (i = 0; i < CTPOLY2_BYTES; ++i)
        data->coeffs[i] = (int16_t)bytes[i] & 0x7f;

    uint8_t tmp[CTPOLY2_BYTES] = { 0 };
    int16_t buf[DATA_OFFSET * 7] = { 0 };
    for (i = 0; i < CTPOLY2_BYTES; ++i)
        tmp[i] = bytes[i] & 0x80;
    load16_littleendian(buf, DATA_OFFSET * 7, tmp);

    int shift[7] = { 1, 2, 3, 4, 5, 6, 7 };
    for (i = 0; i < 2; ++i) {
        for (j = 0; j < DATA_OFFSET; ++j) {
            data->coeffs[d_idx + j] |= (buf[j] >> shift[0]) & 0x40;
            data->coeffs[d_idx + j] |=
                (buf[DATA_OFFSET + j] >> shift[1]) & 0x20;
            data->coeffs[d_idx + j] |=
                (buf[DATA_OFFSET * 2 + j] >> shift[2]) & 0x10;
            data->coeffs[d_idx + j] |=
                (buf[DATA_OFFSET * 3 + j] >> shift[3]) & 0x08;
            data->coeffs[d_idx + j] |=
                (buf[DATA_OFFSET * 4 + j] >> shift[4]) & 0x04;
            data->coeffs[d_idx + j] |=
                (buf[DATA_OFFSET * 5 + j] >> shift[5]) & 0x02;
            data->coeffs[d_idx + j] |=
                (buf[DATA_OFFSET * 6 + j] >> shift[6]) & 0x01;
        }
        d_idx += DATA_OFFSET;
        for (j = 0; j < 7; ++j)
            shift[j] += 8;
    }
#endif
}

void Rp_vec_to_bytes(uint8_t bytes[CTPOLYVEC_BYTES], const polyvec* data) {
    unsigned int i;
    for (i = 0; i < MODULE_RANK; ++i)
        Rp_to_bytes(bytes + i * CTPOLY1_BYTES, &(data->vec[i]));
}

void bytes_to_Rp_vec(polyvec* data, const uint8_t bytes[CTPOLYVEC_BYTES]) {
    unsigned int i;
    for (i = 0; i < MODULE_RANK; ++i)
        bytes_to_Rp(&(data->vec[i]), bytes + i * CTPOLY1_BYTES);
}

void Sx_to_bytes(uint8_t* bytes, const poly* data) {
    unsigned int i;
    int d_idx = 0;
    for (i = 0; i < LWE_N / 4; ++i) {
        d_idx = i * 4;
        bytes[i] = (data->coeffs[d_idx] & 0x03) |       // data->coeff[4*idx + 0] & 0011
            ((data->coeffs[d_idx + 1] & 0x03) << 2) |   // data->coeff[4*idx + 1] & 0011
            ((data->coeffs[d_idx + 2] & 0x03) << 4) |   // data->coeff[4*idx + 2] & 0011
            ((data->coeffs[d_idx + 3] & 0x03) << 6);    // data->coeff[4*idx + 3] & 0011 을
    }                                                   // byte[i] = coef[3] | coef[2] | coef[1] | coef[0] 으로 저장
}

void bytes_to_Sx(poly* data, const uint8_t* bytes) {
    unsigned int i;
    int d_idx = 0;
    for (i = 0; i < LWE_N / 4; ++i) {
        d_idx = i * 4;
        uint8_t t[4] = { 0 };
        t[0] = (bytes[i] & 0x03);
        t[1] = ((bytes[i] >> 2) & 0x03);
        t[2] = ((bytes[i] >> 4) & 0x03);
        t[3] = ((bytes[i] >> 6) & 0x03);
        data->coeffs[d_idx] = t[0] | (-(t[0] >> 1));
        data->coeffs[d_idx + 1] = t[1] | (-(t[1] >> 1));
        data->coeffs[d_idx + 2] = t[2] | (-(t[2] >> 1));
        data->coeffs[d_idx + 3] = t[3] | (-(t[3] >> 1));
    }
}


#if SMAUG_MODE == 1

static void sp_cbd1(poly* r, const uint8_t buf[CBDSEED_BYTES]) {
    unsigned int i, j;
    uint32_t t, d, s;
    int16_t a;

    for (i = 0; i < LWE_N / 8; i++) {
        t = load24_littleendian(buf + 3 * i);   // 0x00249249 -> 0010 0100 1001 0010 0100 1001
        d = t & 0x00249249;                     // t의 001 001 001 001 001 001 001 001 bit를 d에 저장
        d &= (t >> 1) & 0x00249249;             // t의 010 010 010 010 010 010 010 010 bit를 중 위의 d와 똑같이 1일 경우 d에 저장 
        // 위의 두 과정을 통해 서로 다른 값을 x & y 한 것과 같음
        s = (t >> 2) & 0x00249249;              // t의 100 100 100 100 100 100 100 100 bit를 s에 저장

        for (j = 0; j < 8; j++) {
            a = (d >> (3 * j)) & 0x1;           // x & y의 한 비트씩을 a로 저장
            r->coeffs[8 * i + j] =
                a * (((((s >> (3 * j)) & 0x1) - 1) ^ -2) | 1);
        }       // s의 해당 bit가 1이라면,  a * ( ( 0 ^ -2) | 1 ) = a * ( -2 | 1 ) = a * -1
    }           // s의 해당 bit가 0이라면,  a * ( (-1 ^ -2) | 1 ) = a * (  1 | 1 ) = a *  1
}               // x, y에서 모두 1 -> d = 1 (1/4), x,y,s 가 1 -> -1, x,y가 1, s가 0 -> 1, 나머지 -> 0 이므로 1 (1/8), -1 (1/8), 0 (3/4) 인 spCBD이다.
#endif

#if SMAUG_MODE == 3

static void cbd(poly* r, const uint8_t buf[CBDSEED_BYTES]) {
    unsigned int i, j;
    uint32_t t;
    int16_t a, b;

    for (i = 0; i < LWE_N / 16; i++) {
        t = load32_littleendian(buf + 4 * i);

        for (j = 0; j < 16; j++) {
            a = (t >> (2 * j + 0)) & 0x01;
            b = (t >> (2 * j + 1)) & 0x01;
            r->coeffs[16 * i + j] = a - b;
        }
    }
}
#endif

#if SMAUG_MODE == 5

static void sp_cbd2(poly* r, const uint8_t buf[CBDSEED_BYTES]) {
    unsigned int i, j;
    uint32_t t, s, d;
    int16_t a;

    for (i = 0; i < LWE_N / 8; i++) {
        t = load32_littleendian(buf + 4 * i);
        d = t & 0x11111111;
        d |= (t >> 1) & 0x11111111;
        d &= (t >> 2) & 0x11111111;
        s = (t >> 3) & 0x11111111;
        for (j = 0; j < 8; j++) {
            a = (d >> (4 * j)) & 0x1;
            r->coeffs[8 * i + j] = a * (((((s >> (4 * j)) & 0x1) - 1) ^ -2) | 1);
        }
    }
}
#endif

void shake256_absorb_twice_squeeze(uint8_t* out, size_t out_bytes,
    const uint8_t* in1, size_t in1_bytes,
    const uint8_t* in2, size_t in2_bytes) {
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, in1, in1_bytes);
    shake256_absorb(&state, in2, in2_bytes);
    shake256_finalize(&state);
    shake256_squeeze(out, out_bytes, &state);
}




int addGaussianError(poly* op, const uint8_t* seed) {
    unsigned int i = 0, j = 0, k = 0;
    uint64_t seed_temp[SEED_LEN] = { 0 };
    uint8_t buf[SEED_LEN * 8] = { 0 };
    uint64_t s[SLEN] = { 0 };
    uint64_t* x = NULL;

    shake256(buf, SEED_LEN * 8, seed, CRYPTO_BYTES + 1);
    load64_littleendian(seed_temp, SEED_LEN, buf);

    for (i = 0; i < LWE_N; i += 64) {
        x = seed_temp + j;
        s[0] = (x[0] & x[1] & x[2] & x[3] & x[4] & x[5] & x[7] & ~x[8]) |
            (x[0] & x[3] & x[4] & x[5] & x[6] & x[8]) |
            (x[1] & x[3] & x[4] & x[5] & x[6] & x[8]) |
            (x[2] & x[3] & x[4] & x[5] & x[6] & x[8]) |
            (~x[2] & ~x[3] & ~x[6] & x[8]) | (~x[1] & ~x[3] & ~x[6] & x[8]) |
            (x[6] & x[7] & ~x[8]) | (~x[5] & ~x[6] & x[8]) |
            (~x[4] & ~x[6] & x[8]) | (~x[7] & x[8]);
        s[1] = (x[1] & x[2] & x[4] & x[5] & x[7] & x[8]) |
            (x[3] & x[4] & x[5] & x[7] & x[8]) | (x[6] & x[7] & x[8]);
        for (k = 0; k < 64; ++k) {
            op->coeffs[i + k] =
                ((s[0] >> k) & 0x01) | (((s[1] >> k) & 0x01) << 1);
            uint16_t sign = (x[9] >> k) & 0x01;
            op->coeffs[i + k] = (((-sign) ^ op->coeffs[i + k]) + sign)
                << _16_LOG_Q;
        }
        j += RAND_BITS;
    }

    return 0;
}

void addGaussianErrorVec(polyvec* op, const uint8_t seed[CRYPTO_BYTES]) {
    unsigned int i;
    uint8_t extseed[CRYPTO_BYTES + 1] = { 0 };
    memcpy(extseed, seed, CRYPTO_BYTES);            // extseed[0~31] = seed[0~31]
    for (i = 0; i < MODULE_RANK; ++i) {
        extseed[CRYPTO_BYTES] = MODULE_RANK * i;    // extseed[32] = i * MODULE_RANK
        addGaussianError(&(op->vec[i]), extseed);   // Error값 e 생성, 이 때 side channel attack을 막기 위해 [-3,3]이 아닌 <<6 을 진행한 {-192, -128, -64, 0, 64, 128, 192}으로 e 생성
    }
}

// referenced
// Décio Luiz Gazzoni Filho and Tomás S. R. Silva and Julio López
// “Efficient isochronous fixed-weight sampling with applications to {NTRU},” in
// Cryptology {ePrint} Archive, Paper 2024/548. 2024,
// url: eprint.iacr.org/2024/548.
/*************************************************
 * Name:        rejsampling_mod
 *
 * Description: Sample array of random integers such that res[i] is in the range
 *              [0, LWE_N - i] for 0 <= i < LWE_N
 *
 * Arguments:   - uint8_t *res: pointer to ouptput polynomial r(x)
 *                (of length LWE), assumed to be already initialized
 *              - uint8_t *seed: pointer to input seed (of length
 *input_size)
 * 즉, res[i] 에 [0, 256 - i)를 비 편향적으로 sampling하는 코드임
 **************************************************/
static int rejsampling_mod(int16_t res[LWE_N], const uint16_t* rand) {
    unsigned int i, j = LWE_N;
    uint32_t m;
    uint16_t s, t, l;

    // rand 배열은 XOF를 통한 308개짜리 배열임

    for (i = 0; i < LWE_N; i++) {
        s = LWE_N - i;              // s = 256 - i
        t = 65536 % s;              // 2^L mod s

        m = (uint32_t)rand[i] * s;  // m = rand[i] * (256 - i)
        l = m;                      // l = m

        while (l < t) {             // rand[i] * (256 - i)  <  2^L mod 256 - i 이 거짓일 때 까지    - rand[i]가 언제나 범위 [ 0, 2^L / (256 - i) )에 존재하도록(비 편향적이게 하도록) 하는 조건
            if (j >= (HWTSEEDBYTES / 2))    // rand는 0 ~ 308 개짜리 배열이기 때문에 rand[308]은 존재 할 수 없음 -> 이 경우 reject
                return -1; // all randomness used
            m = (uint32_t)rand[j++] * s;    // m = rand[256++] * s
            l = m;                          // l = m
        }

        res[i] = m >> 16;           // rand[i] * (256 - i) or rand[256++] * (256 - i) >> 16
    }

    return 0;
}

int hwt(int16_t* res, const uint8_t* seed) {
    unsigned int i;
    int16_t si[LWE_N] = { 0 };
    uint16_t rand[HWTSEEDBYTES / 2] = { 0 };
    uint8_t sign[LWE_N / 4] = { 0 };
    uint8_t buf[HWTSEEDBYTES] = { 0 };

    keccak_state state;
    shake256_init(&state);
    shake256_absorb_once(&state, seed, CRYPTO_BYTES + 2);

    // only executed once with overwhelming probability:
    shake256_squeeze(buf, HWTSEEDBYTES, &state);        // sampling을 위한 값을 seed를 통해 생성

    load16_littleendian(rand, HWTSEEDBYTES / 2, buf);   // sampling 할 값을(uint8_t)  (int16_t) 형식으로 변경
    if (rejsampling_mod(si, rand))                      // rejection sampling을 진행
    {
        return -1;                                      // 이 때, rejection sampling을 하는 배열은 308개의 배열인데, 해당하는 배열로 원하는 값을 sampling하지 못하면 
    }                                                   // 사용하는 seed값을 변경하기 위해서 return -1

    shake256_squeeze(sign, LWE_N / 4, &state);          // hamming weight의 결과 값을 위한 sign 값을 생성

    int16_t t0;
    int16_t c0 = LWE_N - HS;        // 256 - 70 = 186
    for (i = 0; i < LWE_N; i++) {
        t0 = (si[i] - c0) >> 15;    // si[i] - c0 가 양수 -> 0   (si[i]의 값이 c0보다 크면)
        //               음수 -> -1  (si[i]의 값이 c0보다 작으면)

        c0 += t0;                   //               c0 + 0
        //               c0 - 1

        res[i] = 1 + t0;            // res = 1 + t0  양수 -> 1, 음수 -> 0
        // 즉, si[i]가 c0보다 클 때마다 res[i]에 1의 값을 넣어주는데,
        // 여기에서 c0보다 작으면 c0의 값을 -1 해주는 것으로 res[i]에 1을 넣을 범위를 늘려줌
        // 결국 계속해서 si[i]가 c0보다 작다면 맨 마지막 70개에 대해서는 무조건 c0보다 작아지기 때문에
        // 고정된 Hamming weight를 갖게 됨

        // Convert to ternary
        // index of sign: (i / 16 / 8) * 16 + (i % 16)
        // shift size   : (i / 16) % 8
        res[i] =
            (-res[i]) &
            ((((sign[(((i >> 4) >> 3) << 4) + (i & 0x0F)] >> ((i >> 4) & 0x07)) << 1) & 0x02) - 1); // = res_sign
    }           //  -res[i] & ( ( ( {sign[i / 16 / 8 * 16 + i % 16] >> (i / 16 % 8)}  << 1 ) & 0x02 ) - 1 )
                //                                                                    << 1 연산을 통해 해당 bit를 masking 하는 것과 같은 효과를 볼 수 있음
                //                  0x01이 아닌, << 1 & 0x02 를 한 이유는 하위 2bit를 남기고 싶기 때문에 즉, sign[index_of_sign]의 해당 bit 값이 1 -> (-res[i] & 1) -> 1,  0 -> (-res[i] & -1) -> -1로 남기기 위해서임

                //                  i : 0   ~ 127 -> index of sign : 0  ~ 15 를 반복, shift size : 0 ~ 7 까지 1씩 증가  -> ( (sign[0  ~ 15]의 모든 bit를 << 1 ) & 0x02) - 1 
                //                  i : 128 ~ 256 -> index of sign : 16 ~ 31 을 반복, shift size : 0 ~ 7 까지 1씩 증가  -> ( (sign[16 ~ 31]의 모든 bit를 << 1 ) & 0x02) - 1
                //                  
                // 결국 res[i] 에는 hamming weight HS짜리 +- 1인 작은 정보가 저장되게 됨
    return 0;

}

void poly_cbd(poly* r, const uint8_t buf[CBDSEED_BYTES]) {
#if SMAUG_MODE == 1
    sp_cbd1(r, buf);
#elif SMAUG_MODE == 3
    cbd(r, buf);
#elif SMAUG_MODE == 5
    sp_cbd2(r, buf);
#endif
}




void computeC1(polyvec* c1, const polyvec A[MODULE_RANK], const polyvec* r) {
    unsigned int i, j;

    // c1 = A * r
    matrix_vec_mult_add(c1, A, r);

    // Rounding q to p
    for (i = 0; i < MODULE_RANK; ++i) {
        for (j = 0; j < LWE_N; ++j) {
            c1->vec[i].coeffs[j] =
                ((c1->vec[i].coeffs[j] + RD_ADD) & RD_AND) >> _16_LOG_P;
        }
    }
}

void computeC2(poly* c2, const uint8_t delta[DELTA_BYTES], const polyvec* b,
    const polyvec* r) {
    unsigned int i, j;

    // c2 = q/2 * delta
    for (i = 0; i < DELTA_BYTES; ++i) {
        for (j = 0; j < sizeof(uint8_t) * 8; ++j) {
            c2->coeffs[8 * i + j] = (uint16_t)((delta[i] >> j) << _16_LOG_T);
        }
    }

    // c2 = q/2 * delta + (b * r)
    vec_vec_mult_add(c2, b, r, _16_LOG_Q);

    // Rounding q to p'
    for (i = 0; i < LWE_N; ++i) {
        c2->coeffs[i] = ((c2->coeffs[i] + RD_ADD2) & RD_AND2) >> _16_LOG_P2;
    }
}

void genAx(polyvec A[MODULE_RANK], const uint8_t seed[PKSEED_BYTES]) {
    unsigned int i, j;
    uint8_t buf[PKPOLY_BYTES] = { 0 }, tmpseed[PKSEED_BYTES + 2];
    memcpy(tmpseed, seed, PKSEED_BYTES);                            // tmpseed[0~31] = seed
    for (i = 0; i < MODULE_RANK; i++) {                             
        for (j = 0; j < MODULE_RANK; j++) {
            tmpseed[32] = i;                                        
            tmpseed[33] = j;
            shake128(buf, PKPOLY_BYTES, tmpseed, PKSEED_BYTES + 2); // buf에 값을 생성해서
            bytes_to_Rq(&A[i].vec[j], buf);                         // A에 값을 저장, (상위 10bit -> 실제 A, 하위 6bit -> 의미 없는 값)
        }
    }
}

void genBx(polyvec* b, const polyvec A[MODULE_RANK], const polyvec* s,
    const uint8_t e_seed[CRYPTO_BYTES]) {
    // b = e
    addGaussianErrorVec(b, e_seed); // 생성한 seed[0~31]을 통해 dGaussian 함수로 에러값 생성

    // b = -a * s + e
    matrix_vec_mult_sub(b, A, s);
}

void genSx_vec(secret_key* sk, const uint8_t seed[CRYPTO_BYTES]) {
    unsigned int i, j;
    uint8_t extseed[CRYPTO_BYTES + 2] = { 0 };
    memcpy(extseed, seed, CRYPTO_BYTES);            // extseed에 seed를 저장                               // extseed[0~31] = seed[0~31]

    for (i = 0; i < MODULE_RANK; ++i) {
        extseed[CRYPTO_BYTES] = i * MODULE_RANK;    // seed의 바로 다음 byte를 module_rank * i 로 저장      // extseed[32] = module_rank * i
        j = 0;
        do {
            extseed[CRYPTO_BYTES + 1] = j;          // extseed의 마지막 byte를 j라고 두고,                  // extseed[33] = j
            j += 1;                                 // 해당 j값을 늘려가면서 조건에 맞는 extseed값을 찾아줌
        } while (hwt(sk->vec[i].coeffs, extseed));
    }
}

void genPubkey(public_key* pk, const secret_key* sk,
    const uint8_t err_seed[CRYPTO_BYTES]) {
    genAx(pk->A, pk->seed);                         // seed[32~63]을 통해 A 행렬 생성
                                                    // 생성한 A 행렬은 10bit로 modulo 되어 있지 않고 16bit 표현임, 이후 genBx 함수를 통해서 modulo 연산이 진행됨

    memset(&(pk->b), 0, sizeof(uint16_t) * LWE_N);
    // Initialized at addGaussian, Unnecessary
    genBx(&(pk->b), pk->A, sk, err_seed);           // b = -As + e
}

void genRx_vec(polyvec* r, const uint8_t* input) {
    unsigned int i;
    uint8_t buf[CBDSEED_BYTES] = { 0 };

    for (i = 0; i < MODULE_RANK; ++i) {
        uint8_t extseed[DELTA_BYTES + 1];
        memcpy(extseed, input, DELTA_BYTES);
        extseed[DELTA_BYTES] = i;

        shake256(buf, CBDSEED_BYTES, extseed, DELTA_BYTES + 1);
        poly_cbd(&r->vec[i], buf);
    }
}



void save_to_string(uint8_t* output, const ciphertext* ctxt) {
    Rp_vec_to_bytes(output, &(ctxt->c1));
    Rp2_to_bytes(output + CTPOLYVEC_BYTES, &(ctxt->c2));
}

void load_from_string(ciphertext* ctxt, const uint8_t* input) {
    bytes_to_Rp_vec(&(ctxt->c1), input);
    bytes_to_Rp2(&(ctxt->c2), input + CTPOLYVEC_BYTES);
}

void save_to_string_sk(uint8_t* output, const secret_key* sk) {
    for (size_t i = 0; i < MODULE_RANK; ++i)
        Sx_to_bytes(output + SKPOLY_BYTES * i, &sk->vec[i]);
}

void load_from_string_sk(secret_key* sk, const uint8_t* input) {
    for (size_t i = 0; i < MODULE_RANK; ++i)
        bytes_to_Sx(&sk->vec[i], input + SKPOLY_BYTES * i);
}

void save_to_string_pk(uint8_t* output, const public_key* pk) {
    memcpy(output, pk->seed, sizeof(uint8_t) * PKSEED_BYTES);   // pk[0 ~ 31] = seed[32~63] 로 A행렬 정보 저장
    Rq_vec_to_bytes(output + PKSEED_BYTES, &(pk->b));           // pk[32~351] = b vector를 byte 형식으로 저장
}

void load_from_string_pk(public_key* pk, const uint8_t* input) {
    memcpy(pk->seed, input, PKSEED_BYTES);
    genAx(pk->A, pk->seed);
    bytes_to_Rq_vec(&(pk->b), input + PKSEED_BYTES);
}




void indcpa_keypair(uint8_t pk[PUBLICKEY_BYTES],
    uint8_t sk[PKE_SECRETKEY_BYTES]) {
    public_key pk_tmp;
    secret_key sk_tmp;
    memset(&pk_tmp, 0, sizeof(public_key));
    memset(&sk_tmp, 0, sizeof(secret_key));

    uint8_t seed[CRYPTO_BYTES + PKSEED_BYTES] = { 0 };
    randombytes(seed, CRYPTO_BYTES);                            // seed[0~31] 에 대해 random 값 생성
#if CRYPTO_BYTES + PKSEED_BYTES != 64
#error "This implementation assumes CRYPTO_BYTES + PKSEED_BYTES to be 64"
#endif
    sha3_512(seed, seed, CRYPTO_BYTES);                         // 위에서 생성한 random값을 통해 seed[0~63] 생성

    genSx_vec(&sk_tmp, seed);                                   // 생성한 seed[0~31]을 통해 비밀값 s 생성

    memcpy(&pk_tmp.seed, seed + CRYPTO_BYTES, PKSEED_BYTES);    // pk_tmp.seed에에 생성한 seed[32~63]을 저장
    genPubkey(&pk_tmp, &sk_tmp, seed);                          // seed[32~63]을 통해 A를 생성, 생성한 s와 결합하여 b = -As + e를 생성

    memset(pk, 0, PUBLICKEY_BYTES);                             
    memset(sk, 0, PKE_SECRETKEY_BYTES);
    save_to_string_pk(pk, &pk_tmp);                             // pk = A seed(seed[32~63]) | b  로 저장
    save_to_string_sk(sk, &sk_tmp);                             // sk = s
}

void indcpa_enc(uint8_t ctxt[CIPHERTEXT_BYTES],
    const uint8_t pk[PUBLICKEY_BYTES],
    const uint8_t mu[DELTA_BYTES],
    const uint8_t seed[DELTA_BYTES]) {

    uint8_t seed_r[DELTA_BYTES] = { 0 };
    public_key pk_tmp;
    load_from_string_pk(&pk_tmp, pk);

    // Compute a vector r = hwt(delta, H'(pk))
    polyvec r;
    memset(&r, 0, sizeof(polyvec));

    if (seed == NULL)
        randombytes(seed_r, DELTA_BYTES);
    else
        cmov(seed_r, seed, DELTA_BYTES, 1);
    genRx_vec(&r, seed_r);

    // Compute c1(x), c2(x)
    ciphertext ctxt_tmp;
    memset(&ctxt_tmp, 0, sizeof(ciphertext));
    computeC1(&(ctxt_tmp.c1), pk_tmp.A, &r);
    computeC2(&(ctxt_tmp.c2), mu, &pk_tmp.b, &r);

    save_to_string(ctxt, &ctxt_tmp);
}

void indcpa_dec(uint8_t delta[DELTA_BYTES],
    const uint8_t sk[PKE_SECRETKEY_BYTES],
    const uint8_t ctxt[CIPHERTEXT_BYTES]) {
    poly delta_temp;
    polyvec c1_temp;

    secret_key sk_tmp;
    memset(&sk_tmp, 0, sizeof(secret_key));
    load_from_string_sk(&sk_tmp, sk);

    ciphertext ctxt_tmp;
    load_from_string(&ctxt_tmp, ctxt);

    unsigned int i, j;
    c1_temp = ctxt_tmp.c1;
    delta_temp = ctxt_tmp.c2;
    for (i = 0; i < LWE_N; ++i)
        delta_temp.coeffs[i] <<= _16_LOG_P2;
    for (i = 0; i < MODULE_RANK; ++i)
        for (j = 0; j < LWE_N; ++j)
            c1_temp.vec[i].coeffs[j] <<= _16_LOG_P;

    // Compute delta = (delta + c1^T * s)
    vec_vec_mult_add(&delta_temp, &c1_temp, &sk_tmp, _16_LOG_P);

    // Compute delta = 2/p * delta
    for (i = 0; i < LWE_N; ++i) {
        delta_temp.coeffs[i] += DEC_ADD;
        delta_temp.coeffs[i] >>= _16_LOG_T;
        delta_temp.coeffs[i] &= 0x01;
    }

    // Set delta
    memset(delta, 0, DELTA_BYTES);
    for (i = 0; i < DELTA_BYTES; ++i) {
        for (j = 0; j < 8; ++j) {
            delta[i] ^= ((uint8_t)(delta_temp.coeffs[8 * i + j]) << j);
        }
    }
}


void crypto_kem_keypair(uint8_t* pk, uint8_t* sk) {
    indcpa_keypair(pk, sk);                             // PKE keygen 스킴을 통해 pk, sk 생성
    randombytes(sk + PKE_SECRETKEY_BYTES, T_BYTES);     // 암묵적 거부를 위한 random값 t 생성
    for (int i = 0; i < PUBLICKEY_BYTES; i++)           
        sk[i + PKE_SECRETKEY_BYTES + T_BYTES] = pk[i];  // sk = sk | t | pk 로 저장
}

int crypto_kem_enc(uint8_t* ctxt, uint8_t* ss, const uint8_t* pk) {
    uint8_t mu[DELTA_BYTES] = { 0 }; // shared secret and seed
    uint8_t buf[DELTA_BYTES + CRYPTO_BYTES] = { 0 };

    randombytes(mu, DELTA_BYTES);
    hash_h(buf, pk, PUBLICKEY_BYTES);
    hash_g(buf, DELTA_BYTES + CRYPTO_BYTES, mu, DELTA_BYTES, buf,
        SHA3_256_HashSize);

    memset(ss, 0, CRYPTO_BYTES);
    indcpa_enc(ctxt, pk, mu, buf);
    cmov(ss, buf + DELTA_BYTES, CRYPTO_BYTES, 1);

    return 0;
}


int crypto_kem_dec(uint8_t* ss, const uint8_t* ctxt, const uint8_t* sk) {
    uint8_t mu[DELTA_BYTES] = { 0 };
    uint8_t buf[DELTA_BYTES + CRYPTO_BYTES] = { 0 }; // shared secret and seed
    uint8_t buf_tmp[DELTA_BYTES + CRYPTO_BYTES] = { 0 };
    uint8_t hash_res[SHA3_256_HashSize] = { 0 };
    const uint8_t* pk = sk + PKE_SECRETKEY_BYTES + T_BYTES;

    indcpa_dec(mu, sk, ctxt);
    hash_h(hash_res, pk, PUBLICKEY_BYTES);
    hash_g(buf, DELTA_BYTES + CRYPTO_BYTES, mu, DELTA_BYTES, hash_res,
        SHA3_256_HashSize);

    uint8_t ctxt_temp[CIPHERTEXT_BYTES] = { 0 };
    indcpa_enc(ctxt_temp, pk, mu, buf);


    int fail = verify(ctxt, ctxt_temp, CIPHERTEXT_BYTES);

    hash_h(hash_res, ctxt, CIPHERTEXT_BYTES);
    hash_g(buf_tmp, DELTA_BYTES + CRYPTO_BYTES,
        sk + 2 * MODULE_RANK + SKPOLYVEC_BYTES, T_BYTES, hash_res,
        SHA3_256_HashSize);

    memset(ss, 0, CRYPTO_BYTES);
    cmov(buf + DELTA_BYTES, buf_tmp + DELTA_BYTES, CRYPTO_BYTES, fail);
    cmov(ss, buf + DELTA_BYTES, CRYPTO_BYTES, 1);
    return 0;
}


int main()
{
    uint8_t* pk = (uint8_t*)malloc(PUBLICKEY_BYTES);
    uint8_t* sk = (uint8_t*)malloc(KEM_SECRETKEY_BYTES);

    uint8_t ctxt[CIPHERTEXT_BYTES];
    uint8_t ss[32];
    uint8_t ss2[32];

    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ctxt, ss, pk);
    crypto_kem_dec(ss2, ctxt, sk);

    for (int i = 0; i < 32; i++)
    {
        printf("%02x ", ss[i]);
    }

    printf("\n\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x ", ss2[i]);
    }
    sk = NULL;
    pk = NULL;
    
    return 0;
}
