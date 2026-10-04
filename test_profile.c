/* Correctness checks for both compile-time profiles, using OpenSSL as an
 * independent transcript hash implementation. Build with the library sources. */
#include "raptor.h"
#include <assert.h>
#include <openssl/evp.h>

int main(void)
{
    raptor_data data[NOU];
    unsigned char msg[] = "profile transcript test";
    unsigned char digest[RAPTOR_CHALLENGE_BYTES], expected[RAPTOR_CHALLENGE_BYTES];
    unsigned char changed[RAPTOR_CHALLENGE_BYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sm[CRYPTO_BYTES + sizeof msg], recovered[sizeof msg];
    unsigned long long smlen, mlen;
    int64_t H[DIM];
    EVP_MD_CTX *ctx;
    size_t i, j;
    unsigned char entropy[48] = {0};

    randombytes_init(entropy, NULL, 256);

    for (i = 0; i < NOU; i++) {
        data[i].c = calloc(DIM, sizeof(int64_t));
        data[i].d = calloc(DIM, sizeof(int64_t));
        data[i].h = calloc(DIM, sizeof(int64_t));
        data[i].r0 = calloc(DIM, sizeof(int64_t));
        data[i].r1 = calloc(DIM, sizeof(int64_t));
        assert(data[i].c && data[i].d && data[i].h && data[i].r0 && data[i].r1);
        for (j = 0; j < DIM; j++) data[i].c[j] = (int64_t)(i * DIM + j);
    }
    memset(digest, 0xa5, sizeof digest);
    form_digest(msg, sizeof msg, data, digest);
    ctx = EVP_MD_CTX_new();
    assert(ctx);
#if RAPTOR_FALCON_DEGREE == 512
    assert(EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1);
#else
    assert(EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) == 1);
    assert(EVP_DigestUpdate(ctx, RAPTOR_CHALLENGE_DOMAIN,
                           sizeof RAPTOR_CHALLENGE_DOMAIN - 1) == 1);
#endif
    assert(EVP_DigestUpdate(ctx, msg, sizeof msg) == 1);
    for (i = 0; i < NOU; i++)
        assert(EVP_DigestUpdate(ctx, data[i].c, DIM * sizeof(int64_t)) == 1);
#if RAPTOR_FALCON_DEGREE == 512
    assert(EVP_DigestFinal_ex(ctx, expected, NULL) == 1);
#else
    assert(EVP_DigestFinalXOF(ctx, expected, sizeof expected) == 1);
#endif
    EVP_MD_CTX_free(ctx);
    assert(memcmp(digest, expected, sizeof digest) == 0);
    data[NOU - 1].c[DIM - 1] ^= 1;
    form_digest(msg, sizeof msg, data, changed);
    assert(memcmp(digest, changed, sizeof digest) != 0);
#if RAPTOR_FALCON_DEGREE == 1024
    assert(memcmp(digest + 64, changed + 64, 64) != 0);
#endif
    assert(crypto_sign_keypair(pk, sk) == 0);
    assert((pk[0] & 15) == RAPTOR_LOGN && (sk[0] & 15) == RAPTOR_LOGN);
    assert(crypto_sign(sm, &smlen, msg, sizeof msg, sk) == 0);
    assert(smlen <= sizeof sm);
    assert(crypto_sign_open(recovered, &mlen, sm, smlen, pk) == 0);
    assert(mlen == sizeof msg && memcmp(msg, recovered, sizeof msg) == 0);
    sm[42] ^= 1;
    assert(crypto_sign_open(recovered, &mlen, sm, smlen, pk) == -1);

    for (j = 0; j < DIM; j++) H[j] = (int64_t)(j * 17 % PARAM_Q);
    for (i = 0; i < NOU - 1; i++) assert(raptor_fake_keygen(data[i]) == 0);
    assert(raptor_keygen(data[NOU - 1], sk) == 0);
    assert(raptor_sign(msg, sizeof msg, data, sk, H) == 0);
    assert(raptor_verify(msg, sizeof msg, data, H) == 0);
    msg[0] ^= 1;
    assert(raptor_verify(msg, sizeof msg, data, H) == -1);
    msg[0] ^= 1;
    data[NOU - 1].d[DIM - 1] ^= 1;
    assert(raptor_verify(msg, sizeof msg, data, H) == -1);
    data[NOU - 1].d[DIM - 1] ^= 1;
    data[NOU - 1].r0[DIM - 1] += 1;
    assert(raptor_verify(msg, sizeof msg, data, H) == -1);
    for (i = 0; i < NOU; i++) {
        free(data[i].c); free(data[i].d); free(data[i].h);
        free(data[i].r0); free(data[i].r1);
    }
    printf("profile %d correctness passed\n", DIM);
    return 0;
}
