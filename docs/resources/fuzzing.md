# Fuzzing

[← Home](../../README.md) · [Topic index](../INDEX.md)

Fuzzing belongs in a modern red-team and vulnerability-research toolkit because it turns parser, protocol, file-format, API, and memory-safety assumptions into repeatable test cases.

## Core engines and platforms

- [AFL++](https://github.com/AFLplusplus/AFLplusplus) - coverage-guided fuzzing with source, binary-only, QEMU, Unicorn, Frida, and custom mutator modes.
- [libFuzzer](https://llvm.org/docs/LibFuzzer.html) - in-process LLVM coverage-guided fuzzing engine.
- [Honggfuzz](https://github.com/google/honggfuzz) - security-oriented fuzzer with multiple instrumentation modes.
- [Centipede](https://github.com/google/centipede) - scalable coverage-guided fuzzing engine from Google.
- [OSS-Fuzz](https://google.github.io/oss-fuzz/) - continuous fuzzing service for open source projects.
- [ClusterFuzzLite](https://github.com/google/clusterfuzzlite) - CI-oriented continuous fuzzing for pull requests and scheduled jobs.

## Language and target-specific fuzzers

- [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer) - coverage-guided fuzzing for JVM languages.
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) - libFuzzer integration for Rust.
- [go-fuzz](https://github.com/dvyukov/go-fuzz) - historical Go fuzzing engine; compare with native Go fuzzing for current projects.
- [atheris](https://github.com/google/atheris) - coverage-guided Python fuzzing.
- [jsfuzz](https://github.com/fuzzitdev/jsfuzz) - coverage-guided fuzzing for JavaScript.
- [boofuzz](https://github.com/jtpereyda/boofuzz) - network protocol fuzzing framework.

## Supporting tooling

- [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) - memory error detector.
- [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) - undefined behavior detector.
- [MemorySanitizer](https://clang.llvm.org/docs/MemorySanitizer.html) - uninitialized memory read detector.
- [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator) - structure-aware fuzzing with protobuf grammars.
- [Fuzz Introspector](https://github.com/ossf/fuzz-introspector) - fuzzing coverage and target analysis.

## Minimum useful workflow

1. Pick code that consumes attacker-controlled input: parser, decoder, auth boundary, protocol handler, file upload, or message queue consumer.
2. Build with sanitizers and coverage instrumentation.
3. Write a narrow harness that reaches one risky API without network, sleep, randomness, or external services.
4. Seed with valid minimal samples plus malformed edge cases.
5. Run locally first, minimize corpus, then move into CI or OSS-Fuzz/ClusterFuzzLite.
6. Save crashing inputs as regression tests before patching.

## Bug classes fuzzing finds well

- Out-of-bounds read/write, use-after-free, double-free, integer overflow, stack overflow.
- Parser differentials, deserialization bugs, compression/decompression edge cases.
- Denial of service through hangs, memory blowups, catastrophic backtracking, and algorithmic complexity.
- Logic bugs when paired with property-based assertions or differential oracles.
