# Makefile for the Raptor reference implementation.
# Written for macOS (clang) but also works with gcc on Linux.
#
# Usage:
#   make                    build with default params (NOU=50)
#   make NOU=10             build with a different ring size
#   make FALCON=1024        build extended Falcon-1024 C baseline
#   make run                build (if needed) and run the self-test
#   make run NOU=10         same, with an overridden ring size
#   make bench              build+run across a sweep of ring sizes
#   make clean              remove build artifacts
#
# FALCON selects a complete degree profile; PARAM_Q remains fixed.

CC      ?= cc
BUILD   := build

FALCON      ?= 512
ifneq ($(FALCON),512)
ifneq ($(FALCON),1024)
$(error FALCON must be 512 or 1024)
endif
endif
NOU         ?= 50
SIGMA       ?= 123
PARAM_NONCE ?= 40

# rng/rng.c links OpenSSL (EVP AES-256-ECB) for the DRBG. macOS ships no
# system OpenSSL headers, so this first looks for a Homebrew install.
# Linux distros (Arch, etc.) that install openssl headers straight into
# /usr are picked up as a fallback. Override with
# `make OPENSSL_PREFIX=/path/to/openssl` if yours lives elsewhere.
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl@1.1 2>/dev/null || brew --prefix openssl 2>/dev/null)

ifeq ($(strip $(OPENSSL_PREFIX)),)
  ifneq ($(wildcard /usr/include/openssl/evp.h),)
    OPENSSL_PREFIX := /usr
  endif
endif

ifeq ($(strip $(OPENSSL_PREFIX)),)
$(error Could not find OpenSSL. macOS: brew install openssl@3   Arch: sudo pacman -S openssl   (or pass OPENSSL_PREFIX=/path/to/openssl))
endif

CFLAGS  := -O2 -Wall
PROFILE_FLAGS := -I$(OPENSSL_PREFIX)/include -DRAPTOR_FALCON_DEGREE=$(FALCON) \
                 -DNOU=$(NOU) -DSIGMA=$(SIGMA) -DPARAM_NONCE=$(PARAM_NONCE)
COMPILE_FLAGS := $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(PROFILE_FLAGS)
LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lcrypto -lm

SRCS := raptor.c linkable_raptor.c poly.c print.c test.c \
        rng/crypto_hash_sha512.c rng/fastrandombytes.c rng/rng.c rng/shred.c \
        falcon/crypto_stream.c falcon/falcon-enc.c falcon/falcon-fft.c \
        falcon/falcon-keygen.c falcon/falcon-sign.c falcon/falcon-vrfy.c \
        falcon/frng.c falcon/nist.c falcon/shake.c

PROFILE_DIR := FALCON-$(FALCON)-NOU-$(NOU)-SIGMA-$(SIGMA)-NONCE-$(PARAM_NONCE)
SELF_DIR := $(BUILD)/self/$(PROFILE_DIR)
TARGET := $(SELF_DIR)/raptor
OBJS := $(addprefix $(SELF_DIR)/,$(SRCS:.c=.o))
HEADERS := $(wildcard *.h rng/*.h falcon/*.h)

.PHONY: all run bench clean flags-force

# Preserve the historical executable path for callers. Always refresh it when
# selecting a cached profile, including switches back to an older build.
all: $(TARGET)
	@cp $(TARGET) $(BUILD)/raptor

$(SELF_DIR)/flags: flags-force
	@mkdir -p $(SELF_DIR)
	@printf '%s\n' '$(CC) $(COMPILE_FLAGS) $(LDFLAGS)' > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(SELF_DIR)/%.o: %.c $(HEADERS) $(SELF_DIR)/flags
	@mkdir -p $(@D)
	$(CC) $(COMPILE_FLAGS) -c $< -o $@

run: all
	./$(TARGET)

# Rebuilds and runs at a few ring sizes in one go, printing just the
# timing lines. Handy for the benchmarking section of the report.
bench:
	@for n in 5 10 20 50; do \
		echo "=== NOU=$$n ==="; \
		$(MAKE) --no-print-directory NOU=$$n run 2>&1 | grep "^time"; \
	done

clean:
	rm -rf $(BUILD)

# JSONL adapter builds use separate profile directories from the self-test.
BENCH_DIR := $(BUILD)/bench/$(PROFILE_DIR)
BENCH_TARGET := $(BENCH_DIR)/raptor-bench
BENCH_SRCS := $(filter-out test.c,$(SRCS)) bench.c
BENCH_FLAGS := $(COMPILE_FLAGS)
BENCH_ARGS ?= --suite core --falcon $(FALCON) --samples 10 --warmup 2 --message-bytes 1024
BENCH_HEADERS := $(wildcard *.h rng/*.h falcon/*.h)

.PHONY: bench-build bench-json bench-flags-force
bench-build: $(BENCH_TARGET)

# Update this prerequisite only when compiler/flags actually change.
$(BENCH_DIR)/flags: bench-flags-force
	@mkdir -p $(BENCH_DIR)
	@printf '%s\n' '$(CC) $(BENCH_FLAGS) $(LDFLAGS)' > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

$(BENCH_TARGET): $(BENCH_SRCS) $(BENCH_HEADERS) $(BENCH_DIR)/flags
	@$(CC) $(BENCH_FLAGS) $(BENCH_SRCS) -o $@ $(LDFLAGS) >&2

bench-json: bench-build
	@./$(BENCH_TARGET) $(BENCH_ARGS)

.PHONY: bench-path
bench-path:
	@printf '%s\n' '$(BENCH_TARGET)'

PROFILE_TEST_TARGET := $(SELF_DIR)/profile-test
.PHONY: profile-test
$(PROFILE_TEST_TARGET): $(filter-out test.c,$(SRCS)) test_profile.c $(HEADERS) $(SELF_DIR)/flags
	$(CC) $(COMPILE_FLAGS) $(filter-out test.c,$(SRCS)) test_profile.c -o $@ $(LDFLAGS)

profile-test: $(PROFILE_TEST_TARGET)
	./$(PROFILE_TEST_TARGET)
