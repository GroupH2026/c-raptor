/* Compile-time profiles for the legacy Falcon engine bundled with Raptor. */
#ifndef RAPTOR_PROFILE_H_
#define RAPTOR_PROFILE_H_

#ifndef RAPTOR_FALCON_DEGREE
#define RAPTOR_FALCON_DEGREE 512
#endif

#if RAPTOR_FALCON_DEGREE == 512
#define RAPTOR_LOGN 9
#define RAPTOR_PROFILE_NAME "legacy-falcon-512"
#define RAPTOR_CHALLENGE_NAME "sha512-native-i64-v1"
#define RAPTOR_SIGNATURE_BYTES 690
#define RAPTOR_ALGNAME "Falcon-512"
#elif RAPTOR_FALCON_DEGREE == 1024
#define RAPTOR_LOGN 10
#define RAPTOR_PROFILE_NAME "experimental-falcon-1024"
#define RAPTOR_CHALLENGE_NAME "shake256-domain-native-i64-v1"
#define RAPTOR_CHALLENGE_DOMAIN "raptor-falcon-1024-challenge-v1"
/* Legacy static encoding uses 9 + floor(abs(x)/128) bits/coefficient.
 * The vendored shortness test bounds sum(s2^2) < 7085*12289.
 * Cauchy-Schwarz bounds sum(abs(s2)) <= 298592 at N=1024.
 * Thus payload <= ceil((9*1024 + floor(298592/128))/8) = 1444.
 * Add one signature header, two length bytes, and the 40-byte nonce.
 * This is an encoder capacity, not a modern Falcon signature-size claim. */
#define RAPTOR_SIGNATURE_BYTES 1487
#define RAPTOR_ALGNAME "Falcon-1024-legacy"
#else
#error "RAPTOR_FALCON_DEGREE must be 512 or 1024"
#endif

#define RAPTOR_CHALLENGE_BYTES (RAPTOR_FALCON_DEGREE / 8)
#define RAPTOR_SECRETKEY_BYTES (1 + 8 * RAPTOR_FALCON_DEGREE)
#define RAPTOR_PUBLICKEY_BYTES (1 + 14 * RAPTOR_FALCON_DEGREE / 8)

#endif
