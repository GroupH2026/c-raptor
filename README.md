Raptor: a lattice based (linkable) ring signature
===========
Raptor signature and Reference Code

This repo now includes a Makefile. On macOS you'll need Homebrew's OpenSSL (`brew install openssl@3`), then:

    make              # build with default params (NOU=50)
    make run          # build and run the self-test
    make bench        # run at NOU = 5, 10, 20, 50 and print timings

Three params in `param.h` can be overridden without editing the file, e.g. to test a different ring size:

    make NOU=10 run

| Param | Meaning | Default |
| --- | --- | --- |
| `NOU` | ring size (number of users) | 50 |
| `SIGMA` | Gaussian sampler std dev | 123 |
| `PARAM_NONCE` | Falcon nonce length | 40 |

`DIM` and `PARAM_Q` are fixed by the vendored Falcon-512 implementation and can't be changed this way.



Project Overview
================

![](logo/f22.png)

Raptor (F-22) gets its name from its main building block: [Falcon](https://falcon-sign.info/) signature.
It is the next generation of Falcon (F-16) featured with a stealth mode.


The Raptor cryptography system consists of two component:

* lattice-based ring signature;
* lattice-based one time linkable ring signature.

Status of this code
-----
* Prototype
* non-audited (__use at your own risk!!!__)
* may use the following improvements:
  * signature size compression
  * more efficient discrete Gaussian sampler
  * replace Karatsuba with NTT
  * supporting Falcon-1024
  * removing redundancy
  * strip out NIST wrapper
  * unify the PRNG, XOF, hash, etc

FAQ
===
What is Raptor?
-------------
Raptor is an efficient instantiation of lattice based linkable ring signature.
The paper describing this signature scheme can be found:

  [__Raptor: A Practical Lattice-Based (Linkable) Ring Signature__](https://eprint.iacr.org/2018/857)
  _Xingye Lu_, _Man Ho Au_ and _Zhenfei Zhang_,
  ACNS 2019.


How efficient is Raptor?
-----------------
Raptor is the only implementable lattice based ring signature to date.
The current characteristics are

| Users       |     5    |  10 | 50 |
| ------------- |:-------------:| -----:| -----:|
| KeyGen       | 57 ms | 57 ms |57 ms|
| Sign      | 10.7 ms      |  17.4 ms | 61 ms|
| verification| 5.2 ms     |   11 ms | 50 ms |



It will be more efficient once I finish the todo list.
The estimated signing time will be of the same level as ECC based solutions, i.e., ~ 1 ms per signature.
The size will be

| Users       |     5    |  10 | 50 |
| ------------- |:-------------:| -----:| -----:|
| PK      | 0.9 KB|0.9 KB |0.9 KB|
| SK     |9.1 KB     |  9.1 KB | 9.1 KB|
| Signature|8.8 KB     |  16 KB | 73.8 KB |



Is Raptor Patented?
-----------------
This source code is released under GPL.
The Raptor algorithms are covered, to the best of my knowledge, by the following patents:

* NTRUSIGN (expiring 2021(?))
* ~~NTRU/Falcon based chameleon hash plus scheme; TBA~~
* ~~A new generic framework for ring signature; TBA~~
* ~~Raptor - instantiation of the framework with NTRU/Falcon~~


~The patents will still be enforced but may be used under the GPL,~
~i.e. under the condition that any work that uses them is also made available under the GPL.~
~The patents and the code implementations are also available under standard commercial terms.~

<!---
![](logo/ntru.png)![](logo/obs.png)
--->

JSONL comparison adapter
========================

`bench.c` is a separate measurement driver. It leaves the reference
cryptographic sources and historical `make bench` unchanged. Build each ring
before measurements, then invoke its binary directly throughout the campaign:

```sh
make NOU=5 bench-build
make NOU=10 bench-build
make NOU=20 bench-build
make NOU=50 bench-build
./build/bench/NOU-5-SIGMA-123-NONCE-40/raptor-bench \
  --suite core --falcon 512 --ring-size 5 --samples 100 --warmup 2 \
  --message-bytes 1024 --round 0 > samples.jsonl
```

The adapter binary and compiler-flags record live in a directory specific to
`NOU`, `SIGMA` and `PARAM_NONCE`. Different rings can be built concurrently
without touching the self-test's objects or parameter stamp. Compiler flag
changes trigger rebuilding that adapter. Record the `flags` file, source
hashes, binary hash and command with results. Use a separate copied artifact
for an optimisation sensitivity run. Run `python3 test_bench.py` after building
all four rings to validate JSONL, operation selection and CLI rejection.

`make -s NOU=5 bench-json BENCH_ARGS='--samples 2 --warmup 1'` builds and runs
the adapter for a smoke test. Direct binary invocation avoids build activity
in timed campaign jobs. JSONL goes to stdout; legacy cryptographic diagnostic
prints are redirected to stderr. A failed check exits nonzero without a
`complete` record, retaining earlier successful samples.

The CLI accepts `--suite core`, `--falcon 512`, `--ring-size` matching compiled
`NOU`, `--samples 1..100000`, `--warmup 0..10000`, `--message-bytes
0..1048576`, and an unsigned `--round`. `--operation` selects `keygen`,
`ots-keygen`, `sign`, `verify`, `linkable-sign`, or `linkable-verify`; otherwise
all six cases run. Defaults are 10 samples, two warmups, 1024 message bytes
and round zero. Sample indices start at zero after warmup. Each iteration uses
bytes `32 + ((byte_index + warmup + sample_index) % 95)`.

Timing uses monotonic wall-clock nanoseconds. The driver seeds the C DRBG from
48 bytes of OpenSSL OS entropy once per process, generates real independent
member keys, and puts the signer last as the reference API requires. Caller
buffers are allocated before timing and reused; allocations performed inside
the cryptographic API remain timed. Every generated key and signature passes
an untimed round trip before a verified sample is emitted. Timed verification
checks acceptance. Preflight checks changed-message rejection for basic and
linkable signing, including empty-message requests.

`keygen` times Raptor key generation alone. `ots-keygen` times the separate
Falcon OTS keypair alone. Linkable signing uses basic Raptor ring keys and a
fresh separate OTS pair for each signature, matching the original self-test's
setup. OTS fixture key generation is outside linkable signing timing. This C
OTS construction differs from PQLRS linking and Bulletproof ownership binding.
The driver does not call `linkable_raptor_keygen`, whose additional public-key
masking is a different setup path.

Basic Raptor has no wire encoder, so `output_bytes` is null for basic cases
and key generation. Linkable cases report the returned OTS signed-message
blob length. This is not a complete ring signature encoding: verification
also receives external Raptor data and public parameters.

The unchanged baseline has a known linkable buffer-construction defect. The
copies of `d`, `r0`, `r1` and `h` overlap at byte offsets `base`, `base+1`,
`base+2` and `base+3`, rather than separate polynomial strides. Signing and
verification repeat the same construction, so round trips can succeed while
field binding is defective. Its linkable API also ignores internal signing
return codes; the adapter checks returned length bounds and verifies every
result. These limitations are emitted in the config record. No security or
protocol-equivalence conclusion follows from these timing samples.
