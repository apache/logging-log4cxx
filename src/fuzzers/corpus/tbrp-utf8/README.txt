This directory contains the seed corpus (binary files) for the TimeBasedRollingPolicyFuzzer-utf-8 fuzzer target used by OSS-Fuzz.

These files are packaged into TimeBasedRollingPolicyFuzzer-utf-8_seed_corpus.zip by src/fuzzers/bash/oss-fuzz-build.sh.

Content and provenance:
- The binary seed files were generated deterministically by the script src/fuzzers/corpus/gen_layout_seeds.py
  (run from repo root: python3 src/fuzzers/corpus/gen_layout_seeds.py src/fuzzers/corpus).
- They are crafted to match the FuzzedDataProvider contract used by the harness in src/fuzzers/cpp/TimeBasedRollingPolicyFuzzer.cpp:
  * Front: up to 10 message strings separated by \x5c\x00, consumed by ConsumeRandomLengthString()
  * Back: 4-byte int (BufferedSeconds) + 2 bools (useGz, overwrite) read from the end.
- Purpose: Provide initial high-quality seeds to improve fuzzing coverage for time-based rolling policy features including gz append, zip overwrite, long messages.

Individual files:
- seed-tbrp-gz-append: 3 messages + back bytes for append=true, gz=true
- seed-tbrp-zip-overwrite: 2 messages + large int + back bytes for overwrite
- seed-tbrp-longmsg: long message (256 'f's) + back bytes

These seeds ensure the fuzzer starts with valid inputs exercising the rolling policy logic.
