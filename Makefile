# Makefile for the Raptor reference implementation.
# Written for macOS (clang) but also works with gcc on Linux.
#
# Usage:
#   make                    build with default params (NOU=50)
#   make NOU=10             build with a different ring size
#   make run                build (if needed) and run the self-test
#   make run NOU=10         same, with an overridden ring size
#   make bench              build+run across a sweep of ring sizes
#   make clean              remove build artifacts
#
# Only NOU, SIGMA and PARAM_NONCE are safe to override this way - see
# param.h for why DIM and PARAM_Q are not exposed here.

CC      ?= cc
BUILD   := build
TARGET  := $(BUILD)/raptor

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

CFLAGS  := -O2 -Wall -I$(OPENSSL_PREFIX)/include \
           -DNOU=$(NOU) -DSIGMA=$(SIGMA) -DPARAM_NONCE=$(PARAM_NONCE)
LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lcrypto -lm

SRCS := raptor.c linkable_raptor.c poly.c print.c test.c \
        rng/crypto_hash_sha512.c rng/fastrandombytes.c rng/rng.c rng/shred.c \
        falcon/crypto_stream.c falcon/falcon-enc.c falcon/falcon-fft.c \
        falcon/falcon-keygen.c falcon/falcon-sign.c falcon/falcon-vrfy.c \
        falcon/frng.c falcon/nist.c falcon/shake.c

OBJS  := $(addprefix $(BUILD)/,$(notdir $(SRCS:.c=.o)))
STAMP := $(BUILD)/.params_$(NOU)_$(SIGMA)_$(PARAM_NONCE)

vpath %.c . rng falcon

.PHONY: all run bench clean

all: $(TARGET)

# Object files don't encode which param values they were built with, so
# if NOU/SIGMA/PARAM_NONCE changed since the last build, wipe stale
# objects before compiling - otherwise `make` would silently reuse
# objects built with the old params and give you misleading numbers.
$(STAMP):
	@mkdir -p $(BUILD)
	@rm -f $(BUILD)/*.o $(BUILD)/.params_*
	@touch $@

$(TARGET): $(STAMP) $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

$(BUILD)/%.o: %.c | $(STAMP)
	$(CC) $(CFLAGS) -c $< -o $@

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

# JSONL adapter builds never touch historical self-test objects or parameter stamps.
BENCH_DIR := $(BUILD)/bench/NOU-$(NOU)-SIGMA-$(SIGMA)-NONCE-$(PARAM_NONCE)
BENCH_TARGET := $(BENCH_DIR)/raptor-bench
BENCH_SRCS := $(filter-out test.c,$(SRCS)) bench.c
BENCH_FLAGS := $(CFLAGS) -DNOU=$(NOU) -DSIGMA=$(SIGMA) -DPARAM_NONCE=$(PARAM_NONCE)
BENCH_ARGS ?= --suite core --samples 10 --warmup 2 --message-bytes 1024
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
