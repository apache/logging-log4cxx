This directory contains the seed corpus (binary files) for the XMLLayoutFuzzer-wchar_t fuzzer target used by OSS-Fuzz.

These files are packaged into XMLLayoutFuzzer-wchar_t_seed_corpus.zip by src/fuzzers/bash/oss-fuzz-build.sh.

Content and provenance:
- The binary seed files were generated deterministically by the script src/fuzzers/corpus/gen_layout_seeds.py
  (run from repo root: python3 src/fuzzers/corpus/gen_layout_seeds.py src/fuzzers/corpus).
- They are crafted to match the FuzzedDataProvider contract used by the harness in src/fuzzers/cpp/XMLLayoutFuzzer.cpp (wchar_t encoding variant):
  * Front: 8 fields (k1,v1,k2,v2,ndc,logger,pk,pv) separated by \x5c\x00
  * No back consumption for this harness.
- Purpose: Provide initial high-quality seeds to improve fuzzing coverage for XML layout features including entities, long messages, unicode, CDATA sections (in wchar_t build).

Individual files (identical content to xml-utf8/ as the harness uses the same structure, adapted for wchar_t):
- seed-xml-entities, seed-xml-long, seed-xml-unicode, seed-xml-cdata

These seeds ensure the fuzzer starts with structurally valid inputs for the XML layout logger under wchar_t encoding.
