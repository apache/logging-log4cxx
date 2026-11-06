This directory contains the seed corpus (binary files) for the HTMLLayoutFuzzer-utf-8 fuzzer target used by OSS-Fuzz.

These files are packaged into HTMLLayoutFuzzer-utf-8_seed_corpus.zip by src/fuzzers/bash/oss-fuzz-build.sh.

Content and provenance:
- The binary seed files were generated deterministically by the script src/fuzzers/corpus/gen_layout_seeds.py
  (run from repo root: python3 src/fuzzers/corpus/gen_layout_seeds.py src/fuzzers/corpus).
- They are crafted to match the FuzzedDataProvider contract used by the harness in src/fuzzers/cpp/HTMLLayoutFuzzer.cpp:
  * Front: fields separated by \x5c\x00 (backslash + NUL), consumed by ConsumeRandomLengthString()
  * Back: bytes for ConsumeBool()/ConsumeIntegral()
- Purpose: Provide initial high-quality seeds to improve fuzzing coverage for HTML layout features including entities, long messages, unicode, titles, quotes, etc.

Individual files:
- seed-html-entities: 10 front fields (k1..v4, ndc, logger) + entity XML with &amp; etc. + 3 back bytes
- seed-html-long: same front + long message (512x 'x' + entities + controls) + back bytes
- seed-html-quotes: front fields with special chars (" \ < > & ) + unicode + back bytes
- seed-html-titled: front with title/header content + entity + back bytes
- seed-html-unicode: front + UTF-8 unicode string + back bytes

These seeds ensure the fuzzer starts with structurally valid inputs for the layout logger.
