#ifndef RAPTOR_FALCON_API_H_
#define RAPTOR_FALCON_API_H_

#include "../profile.h"

#define CRYPTO_SECRETKEYBYTES RAPTOR_SECRETKEY_BYTES
#define CRYPTO_PUBLICKEYBYTES RAPTOR_PUBLICKEY_BYTES
#define CRYPTO_BYTES RAPTOR_SIGNATURE_BYTES
#define CRYPTO_ALGNAME RAPTOR_ALGNAME

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk);

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk);

#endif
