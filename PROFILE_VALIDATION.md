# Degree profile validation

Validated on 2026-10-05. These are correctness and campaign-readiness checks,
not thesis performance measurements.

- `python3 test_bench.py`: both degrees at rings 5, 10, 20 and 50; all six
  operations; changed-message rejection; empty messages; invalid CLI arguments;
  warmup/sample indexing; switching 512 to 1024 and back without cleaning.
- `make FALCON=512 NOU=5 profile-test` and the corresponding 1024 test:
  independent OpenSSL SHA-512/SHAKE256 transcript comparison, key dimensions,
  Falcon and Raptor roundtrips, and rejection of message and final-coefficient
  modifications. The 512 transcript matches the original construction.
- AddressSanitizer and UndefinedBehaviorSanitizer passed for both focused
  profile tests using `-DFALCON_LE_U=0`. The default vendored PRNG uses an
  existing unaligned integer load that UBSan rejects; the portable path avoids
  that load. The 1024 adapter also passed with leak detection, three samples
  and one warmup across all six operations.
- The PQLRS campaign runner accepted 16 real C jobs, two rounds of both degrees
  at all four ring sizes, ten samples and two warmups per job: 960 accepted
  observations, zero failed jobs. Local raw JSONL, stderr, executable/source
  hashes and plan are saved under `build/campaign-profile-validation/`.
- Campaign, report, overnight and launch regression tests: 55 tests run,
  one skipped, no failures.

Falcon-1024 is an experimental extension with a new domain-separated challenge
and legacy sigma 123. Passing these checks does not validate its security
parameters or repair the inherited linkable buffer-layout defect described in
the README. Original overnight results remain unchanged.
