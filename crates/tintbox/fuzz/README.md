# tintbox fuzzing

Coverage-guided (libFuzzer) fuzzing of tintbox's untrusted-input surfaces. This
is a **separate crate, detached from the stable-pinned workspace** (note the
empty `[workspace]` table in `Cargo.toml`) and requires nightly + `cargo-fuzz`.

The always-on, zero-setup complement runs on **stable** in the normal test suite
and should catch regressions for every contributor without nightly:

- `crates/tintbox/tests/malformed_icc.rs`
- `crates/tintbox/tests/malformed_cgats.rs`

Those deepen on demand: `TINTBOX_FUZZ_ITERS=200000 cargo test -p tintbox`.

## Why these targets

tintbox is `#![forbid(unsafe_code)]`, so the lcms2 memory-corruption CVE classes
(heap overflow, OOB r/w, double free, UAF) are unreachable by construction. What
fuzzing hunts here is the *residual* class for a safe-Rust parser of hostile
input: **panics** (`unwrap`/index/overflow → process-killing DoS), **unbounded
allocation/CPU**, and — uniquely — **divergence from lcms2**.

| Target | Surface | lcms2 CVE neighbourhood |
|---|---|---|
| `icc_profile` | ICC parse + tag/LUT/TAC/blackpoint/PostScript decode | CVE-2016-10165, CVE-2013-7455, CVE-2026-41254 |
| `icc_differential` | same bytes through tintbox **and** lcms2; assert accept/reject, tag-set, and TAC parity | turns "bit-identical" from claimed into demonstrated |
| `cgats_it8` | CGATS / IT8.7 tabular parser | CVE-2018-16435 (integer-overflow → undersized alloc) |
| `transform_packed` | pack/unpack/eval kernels (structured `arbitrary` input) | CVE-2025-29069 (`UnrollChunkyBytes`) |

`[profile.release]` sets `overflow-checks = true` so attacker-controlled size
arithmetic that would *silently wrap* in a normal release build instead panics
and is caught as a crash — directly targeting the integer-overflow shape that
dominates the lcms2 CVE history.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly

# Seed corpora from the vendored lcms2 test profiles (already in-tree):
mkdir -p corpus/icc_profile corpus/icc_differential
cp ../../../vendor/Little-CMS/testbed/*.icc corpus/icc_profile/
cp ../../../vendor/Little-CMS/testbed/*.icc corpus/icc_differential/

cargo +nightly fuzz run icc_profile
cargo +nightly fuzz run icc_differential
cargo +nightly fuzz run cgats_it8
cargo +nightly fuzz run transform_packed

# Reproduce / minimise a crash:
cargo +nightly fuzz run icc_profile fuzz/artifacts/icc_profile/crash-<hash>
cargo +nightly fuzz tmin icc_profile fuzz/artifacts/icc_profile/crash-<hash>
```

A crash file that reproduces should become a one-line regression case in the
stable `tests/malformed_*.rs` files, so it is guarded forever without nightly.

## OSS-Fuzz parity

The `icc_profile` op-set mirrors lcms2's own libFuzzer entry
(`vendor/Little-CMS/fuzzers/fuzzers.c::LLVMFuzzerTestOneInput`), the same surface
Google OSS-Fuzz drives against lcms2 — so the engines are fuzzed like-for-like,
and `icc_differential` additionally cross-checks their results.
