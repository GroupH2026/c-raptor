#define _POSIX_C_SOURCE 200809L
#include "raptor.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>

/* Measurement adapter for the compiled C profile. */
static FILE *records;
static size_t samples = 10, warmup = 2, message_bytes = 1024, round_id;
static const char *operation;
static size_t emitted;
static const char *cases[] = {"keygen", "ots-keygen", "sign", "verify", "linkable-sign", "linkable-verify"};

static void require(int ok, const char *context) {
    if (!ok) { fprintf(stderr, "c-raptor benchmark failed: %s\n", context); exit(1); }
}
static uint64_t now_ns(void) {
    struct timespec t;
    require(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "monotonic clock");
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static size_t number(const char *s) {
    char *end;
    unsigned long long n;
    require(*s >= '0' && *s <= '9', "expected unsigned decimal option");
    errno = 0; n = strtoull(s, &end, 10);
    require(!errno && !*end && n <= SIZE_MAX, "invalid numeric option");
    return (size_t)n;
}
static int basic_only(void) { return operation && strcmp(operation, "basic") == 0; }
static int selected(const char *name) {
    if (basic_only()) return !strcmp(name, "keygen") || !strcmp(name, "sign") || !strcmp(name, "verify");
    return !operation || strcmp(operation, name) == 0;
}
static void row(const char *name, size_t iteration, uint64_t elapsed, int bytes) {
    if (iteration < warmup || !selected(name)) return;
    fprintf(records, "{\"type\":\"sample\",\"schema_version\":1,\"suite\":\"core\",\"case\":\"%s\",\"implementation\":\"c-raptor\",\"falcon\":%d,\"ring_size\":%d,\"message_bytes\":%zu,\"round\":%zu,\"sample\":%zu,\"elapsed_ns\":%" PRIu64 ",\"output_bytes\":", name, RAPTOR_FALCON_DEGREE, NOU, message_bytes, round_id, iteration-warmup, elapsed);
    if (bytes < 0) fputs("null", records); else fprintf(records, "%d", bytes);
    fputs(",\"phases\":[],\"verified\":true}\n", records);
    require(!ferror(records) && fflush(records) == 0, "sample output");
    emitted++;
}
static void *allocate(size_t n) {
    void *p = calloc(1, n ? n : 1);
    require(p != NULL, "fixture allocation"); return p;
}
static void validate_ots(unsigned char *pk, unsigned char *sk) {
    unsigned char sm[CRYPTO_BYTES + 1], recovered[CRYPTO_BYTES + 1];
    unsigned char message = 42;
    unsigned long long len = 0, recovered_len = 0;
    require(crypto_sign(sm, &len, &message, 1, sk) == 0, "OTS fixture signing");
    require(len <= sizeof sm && crypto_sign_open(recovered, &recovered_len, sm, len, pk) == 0 && recovered_len == 1 && recovered[0] == message, "OTS keypair roundtrip");
}
int main(int argc, char **argv) {
    unsigned char entropy[48], seed[SEEDLEN];
    int out_fd;
    size_t iteration, i;
    uint64_t started, elapsed;
    int length;
    raptor_data data[NOU];
    unsigned char *sk, *discard_sk, *ots_sk, *ots_pk, *ots_sm, *message, *changed;
    int64_t *H;
    const size_t capacity = 4 * sizeof(int64_t) * DIM * NOU + CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES;
    for (int arg = 1; arg < argc; arg++) {
        const char *key = argv[arg], *value;
        if (!strcmp(key, "--help")) {
            puts("Usage: raptor-bench [--suite core] [--falcon compiled-512-or-1024] [--ring-size compiled-NOU] [--samples 1..100000] [--warmup 0..10000] [--message-bytes 0..1048576] [--round N] [--operation basic|keygen|ots-keygen|sign|verify|linkable-sign|linkable-verify]"); return 0;
        }
        require(arg + 1 < argc, "option needs a value"); value = argv[++arg];
        if (!strcmp(key, "--samples")) samples = number(value);
        else if (!strcmp(key, "--warmup")) warmup = number(value);
        else if (!strcmp(key, "--message-bytes")) message_bytes = number(value);
        else if (!strcmp(key, "--round")) round_id = number(value);
        else if (!strcmp(key, "--suite")) require(!strcmp(value, "core"), "suite must be core");
        else if (!strcmp(key, "--falcon")) require(number(value) == RAPTOR_FALCON_DEGREE, "falcon must match compiled profile");
        else if (!strcmp(key, "--ring-size")) require(number(value) == NOU, "ring-size must match compiled NOU");
        else if (!strcmp(key, "--operation")) operation = value;
        else require(0, "unknown option");
    }
    require(samples >= 1 && samples <= 100000 && warmup <= 10000 && message_bytes <= 1048576, "request outside sample/warmup/message bounds");
    require(NOU >= 3 && NOU <= 128 && capacity <= INT_MAX, "compiled ring outside supported limits");
    if (operation) {
        int found = basic_only();
        for (i = 0; i < sizeof cases / sizeof cases[0]; i++) found |= !strcmp(operation, cases[i]);
        require(found, "unknown operation");
    }
    /* Legacy routines print diagnostic text; retain clean JSONL on original stdout. */
    out_fd = dup(STDOUT_FILENO); require(out_fd >= 0, "duplicate stdout");
    require(dup2(STDERR_FILENO, STDOUT_FILENO) >= 0, "redirect legacy diagnostics");
    records = fdopen(out_fd, "w"); require(records != NULL, "JSONL stream");
    fprintf(records, "{\"type\":\"config\",\"schema_version\":1,\"implementation\":\"c-raptor\",\"options\":{\"suite\":\"core\",\"falcon\":%d,\"ring_size\":%d,\"message_bytes\":%zu,\"samples\":%zu,\"warmup\":%zu,\"round\":%zu},\"profile\":\"%s\",\"challenge\":\"%s\",\"sigma\":%d,\"core_basic_only\":%s,\"clock\":\"CLOCK_MONOTONIC\",\"fixture\":\"independent real ring keys; signer last; per-iteration message\",\"rng\":\"OS-seeded AES256 CTR DRBG\",\"allocation_scope\":\"caller buffers reused; internal API allocations included\",\"linkable_setup\":\"basic Raptor keys plus separate Falcon OTS keypair\",\"output_bytes_scope\":\"null except returned OTS signed-message blob; not complete ring encoding\",\"limitations\":[\"baseline linkable buffer fields overlap at byte offsets +1,+2,+3\",\"linkable API ignores internal signing return codes; adapter validates length and roundtrip\",\"C OTS construction differs from PQLRS linking and Bulletproof binding\"]}\n", RAPTOR_FALCON_DEGREE, NOU, message_bytes, samples, warmup, round_id, RAPTOR_PROFILE_NAME, RAPTOR_CHALLENGE_NAME, SIGMA, basic_only() ? "true" : "false");
    require(fflush(records) == 0, "config output");
    require(RAND_bytes(entropy, sizeof entropy) == 1, "OS entropy");
    randombytes_init(entropy, NULL, 256); memset(entropy, 0, sizeof entropy);
    H = allocate(sizeof(int64_t) * DIM);
    require(randombytes(seed, sizeof seed) == RNG_SUCCESS, "public parameter randomness");
    pol_unidrnd_with_seed(H, DIM, PARAM_Q, seed, sizeof seed);
    sk = allocate(CRYPTO_SECRETKEYBYTES); discard_sk = allocate(CRYPTO_SECRETKEYBYTES);
    ots_sk = ots_pk = ots_sm = NULL;
    if (!basic_only()) {
        ots_sk = allocate(CRYPTO_SECRETKEYBYTES); ots_pk = allocate(CRYPTO_PUBLICKEYBYTES);
        ots_sm = allocate(capacity);
    }
    message = allocate(message_bytes); changed = allocate(message_bytes + 1);
    for (i = 0; i < NOU; i++) {
        data[i].c = allocate(sizeof(int64_t)*DIM); data[i].d = allocate(sizeof(int64_t)*DIM);
        data[i].h = allocate(sizeof(int64_t)*DIM); data[i].r0 = allocate(sizeof(int64_t)*DIM); data[i].r1 = allocate(sizeof(int64_t)*DIM);
        require(raptor_keygen(data[i], i == NOU-1 ? sk : discard_sk) == 0, "real ring member keygen");
    }
    if (!basic_only()) require(crypto_sign_keypair(ots_pk, ots_sk) == 0, "initial OTS keygen");
    require(raptor_sign(message, message_bytes, data, sk, H) == 0 && raptor_verify(message, message_bytes, data, H) == 0, "basic preflight roundtrip");
    memcpy(changed, message, message_bytes); changed[message_bytes] = 1;
    require(raptor_verify(changed, message_bytes + 1, data, H) != 0, "basic changed-message rejection");
    if (!basic_only()) {
        length = linkable_raptor_sign(message, message_bytes, data, sk, H, ots_pk, ots_sk, ots_sm);
        require(length > 0 && (size_t)length <= capacity && linkable_raptor_verify(message, message_bytes, data, H, ots_pk, ots_sm, length) == 0, "linkable preflight roundtrip");
        require(linkable_raptor_verify(changed, message_bytes + 1, data, H, ots_pk, ots_sm, length) != 0, "linkable changed-message rejection");
    }
    for (iteration = 0; iteration < warmup + samples; iteration++) {
        for (i = 0; i < message_bytes; i++) message[i] = 32 + ((i + iteration) % 95);
        if (selected("keygen")) {
            started = now_ns(); require(raptor_keygen(data[NOU-1], sk) == 0, "measured keygen"); elapsed = now_ns()-started;
            require(raptor_sign(message, message_bytes, data, sk, H) == 0 && raptor_verify(message, message_bytes, data, H) == 0, "generated key roundtrip");
            row("keygen", iteration, elapsed, -1);
        }
        if (selected("ots-keygen")) {
            started = now_ns(); require(crypto_sign_keypair(ots_pk, ots_sk) == 0, "measured OTS keygen"); elapsed = now_ns()-started;
            validate_ots(ots_pk, ots_sk); row("ots-keygen", iteration, elapsed, -1);
        }
        if (selected("sign") || selected("verify")) {
            started = now_ns(); require(raptor_sign(message, message_bytes, data, sk, H) == 0, "basic signing"); elapsed = now_ns()-started;
            require(raptor_verify(message, message_bytes, data, H) == 0, "basic untimed verification"); row("sign", iteration, elapsed, -1);
            if (selected("verify")) {
                started = now_ns(); require(raptor_verify(message, message_bytes, data, H) == 0, "basic timed verification"); elapsed = now_ns()-started;
                row("verify", iteration, elapsed, -1);
            }
        }
        if (selected("linkable-sign") || selected("linkable-verify")) {
            if (!selected("ots-keygen")) require(crypto_sign_keypair(ots_pk, ots_sk) == 0, "fresh per-signature OTS fixture");
            memset(ots_sm, 0, capacity);
            started = now_ns(); length = linkable_raptor_sign(message, message_bytes, data, sk, H, ots_pk, ots_sk, ots_sm); elapsed = now_ns()-started;
            require(length > 0 && (size_t)length <= capacity, "linkable output length");
            require(linkable_raptor_verify(message, message_bytes, data, H, ots_pk, ots_sm, length) == 0, "linkable untimed verification"); row("linkable-sign", iteration, elapsed, length);
            if (selected("linkable-verify")) {
                started = now_ns(); require(linkable_raptor_verify(message, message_bytes, data, H, ots_pk, ots_sm, length) == 0, "linkable timed verification"); elapsed = now_ns()-started;
                row("linkable-verify", iteration, elapsed, length);
            }
        }
    }
    fprintf(records, "{\"type\":\"complete\",\"schema_version\":1,\"samples\":%zu,\"verified\":true}\n", emitted);
    require(fclose(records) == 0, "complete output");
    memset(sk, 0, CRYPTO_SECRETKEYBYTES); memset(discard_sk, 0, CRYPTO_SECRETKEYBYTES); if (ots_sk) memset(ots_sk, 0, CRYPTO_SECRETKEYBYTES);
    free(sk); free(discard_sk); free(ots_sk); free(ots_pk); free(ots_sm); free(H); free(message); free(changed);
    for (i = 0; i < NOU; i++) { free(data[i].c); free(data[i].d); free(data[i].h); free(data[i].r0); free(data[i].r1); }
    return 0;
}
