# Changelog

All notable changes to `tintbox` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: the minor version is the breaking-change position).

**Invariant:** every release is verified **byte-for-byte identical to lcms2**
(differential-tested against the C library). Performance changes make the same
bytes faster — they never change a result.

## [Unreleased]

## [0.2.0] - 2026-06-16

Performance release. The default output is unchanged — `Accurate` is still the
default strategy, so 0.1.0 callers see only additions.

### Added
- `OptimizationStrategy::AccurateFast` — an opt-in **lossless** fast path
  (byte-identical to `Accurate` and to lcms2 `cmsFLAGS_NOOPTIMIZE`): exact 8-bit
  input-curve LUTs, a lossless float matrix-shaper (the full-precision analogue of
  lcms2's lossy `MatShaperEval16`), and a batched/tiled u16 stage-by-stage eval.
  ~1.5–2.4× faster than `Accurate` for bulk buffers, and **faster than lcms2's own
  lossless path**. Falls back to the per-pixel path below 256 px/call, so it is
  never slower than `Accurate` at any chunk size.
- Opt-in `simd` feature (the safe `wide` crate): bit-identical SIMD kernels for the
  3×3 matrix (across pixels, f64 lanes, no FMA) and the integer tetrahedral
  interpolation (across output channels). Off by default — zero cost and unchanged
  behavior when disabled; the core remains `#![forbid(unsafe_code)]` and wasm-clean.
  Note: on x86 you must enable the CPU's wide lanes at build time
  (`RUSTFLAGS=-C target-cpu=native` or `x86-64-v3`) or it stays SSE2-narrow.
- Compile-time assertion that `Transform: Send + Sync`, backing the
  consumer-threading model (the library does not thread internally by design; share
  one `Transform` across threads and split the buffer).
- Unrolled `Eval4` 4-input CLUT kernel (lcms2 `Eval4Inputs`) — bit-identical, used
  by both `Accurate` and `AccurateFast` for CMYK-input CLUTs.

### Changed
- Performance (default `Accurate` path, all bit-identical): hoisted the per-pixel
  `Context::new()` out of curve evaluation (was ~13.5% self-time), removed the
  per-pixel `Vec` allocation from the non-batched eval, and removed a per-tile
  `Context` construction from the batched path.
- README gained a **Performance** section (batching guidance, the consumer-threading
  rationale + example, the `simd` feature, and the x86 build flags).

### Notes
- The remaining speed gap to lcms2's *default* optimizer is its **lossy** device-link
  bake (14–17% shadow drift), reproducible bit-for-bit via the opt-in
  `OptimizationStrategy::Lcms2Compat` if a fast-preview mode is ever wanted.
- `AccurateFast` trades higher one-time transform-*construction* cost (it precomputes
  LUTs/plan, ~2.4 ms for a CMYK link vs ~0.15 ms) for faster per-pixel throughput, so
  it pays off for build-once-convert-many usage (cache the `Transform`, the idiom).

## [0.1.0] - 2026-06-15

Initial release: a from-scratch, pure-Rust, full-parity reimplementation of
Little CMS (lcms2 2.19.1), `#![forbid(unsafe_code)]`, `std` + abstract I/O,
wasm-ready, and verified bit-identical to the C library by differential testing.

### Added
- **Profile I/O** — ICC header + tag directory + every tag-type reader **and**
  byte-exact writer (round-trips through both stacks).
- **Tone curves & PCS** — all 20 parametric types (+ inverses), tabulated/segmented
  curves, Lab/XYZ/LCh/xyY, Bradford chromatic adaptation.
- **Pipelines** — `Stage` pipeline + n-D interpolation (tetrahedral/trilinear/…),
  LUT/MPE tags.
- **Transforms** — `cmsCreateTransform`/`cmsDoTransform` equivalents, all four
  rendering intents, absolute-colorimetric + black-point compensation, and
  black-point detection-by-sampling.
- **Pixel formats** — packed `TYPE_*` 8/16/float/double, RGB/CMYK/Gray/Lab/XYZ,
  swap/flavor/endian, alpha copy.
- **Optimization strategies** — `Accurate` (lossless, default) and `Lcms2Compat`
  (matches stock lcms2-default, including the CLUT-baking optimizer).
- **Virtual/built-in profiles** — sRGB, RGB, gray, Lab2/Lab4, XYZ, NULL,
  linearization device-link — byte-identical to `cmsCreate*Profile`.
- **Peripheral subsystems** — CGATS/IT8.7, CIECAM02, PostScript CSA/CRD, named/spot
  colors, gamut boundary + `cmsDetectTAC` + proofing/gamut-check.
- **Extensibility** — lcms2's plugin categories as idiomatic Rust traits (parametric
  curves, tag types, rendering intents, optimizers, interpolators), consulted
  builtins-first so they cannot perturb the bit-identical defaults.

[Unreleased]: https://github.com/RayVR/tintbox/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/RayVR/tintbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/RayVR/tintbox/releases/tag/v0.1.0
