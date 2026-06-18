//! Untrusted-input robustness + differential parity for the ICC-profile
//! parse/decode surface — the highest-risk path in any real deployment, since
//! ICC profiles arrive embedded in arbitrary PDFs and images.
//!
//! # What this guards
//!
//! tintbox is `#![forbid(unsafe_code)]`, so the lcms2 memory-corruption CVE
//! classes — heap overflow from integer overflow (CVE-2018-16435,
//! CVE-2026-41254), OOB read/write (CVE-2016-10165), double free
//! (CVE-2013-7455), use-after-free — are out of reach *by construction*: safe
//! indexing panics instead of corrupting memory, and ownership rules forbid the
//! lifetime bugs outright. What safe Rust does **not** eliminate is the residual
//! failure mode this file targets:
//!
//!  - **Panic-as-DoS.** An `unwrap`/index/overflow on malformed input aborts the
//!    process. Harmless on a desktop, a production outage in a server-side PDF
//!    pipeline. Every assertion below is ultimately "tintbox did not panic."
//!  - **Accept/reject + structural divergence** from the reference engine on
//!    *valid* profiles (the project's bit-identity invariant).
//!
//! # How
//!
//! The op-set in [`exercise_full`] mirrors lcms2's own libFuzzer entry point
//! (`vendor/Little-CMS/fuzzers/fuzzers.c`, `LLVMFuzzerTestOneInput`): open from
//! memory, read every tag (parsed + raw), read input/output/devicelink LUTs
//! across all four intents, detect black point and TAC, and generate PostScript
//! CSA/CRD. The same surface Google OSS-Fuzz drives against lcms2 is driven
//! against tintbox here — but on stable, in `cargo test`, with the `tintbox`
//! engine differentially checked against the `cc`-built lcms2 oracle.
//!
//! For a deep, coverage-guided campaign (libFuzzer/AFL, structured `arbitrary`
//! inputs), see `crates/tintbox/fuzz/`. This file is the always-on, zero-setup
//! complement that runs for every contributor.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use tintbox::format::decode::{TYPE_CMYK_8, TYPE_GRAY_8, TYPE_RGB_8};
use tintbox::gamut::detect_tac;
use tintbox::link::black_point::{detect_black_point, detect_destination_black_point};
use tintbox::link::{read_devicelink_lut, read_input_lut, read_output_lut};
use tintbox::profile::virtuals::build_srgb_profile;
use tintbox::profile::{ColorSpace, Profile, RenderingIntent};
use tintbox::ps::{get_post_script_crd, get_post_script_csa};
use tintbox::sig::Signature;
use tintbox::transform::Transform;

fn testbed_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vendor/Little-CMS/testbed"
    ))
}

fn read_testbed(name: &str) -> Vec<u8> {
    fs::read(testbed_dir().join(name)).unwrap_or_else(|_| panic!("read {name}"))
}

const INTENTS: [RenderingIntent; 4] = [
    RenderingIntent::Perceptual,
    RenderingIntent::RelativeColorimetric,
    RenderingIntent::Saturation,
    RenderingIntent::AbsoluteColorimetric,
];

/// The full decode surface, mirroring lcms2's `LLVMFuzzerTestOneInput`. Every
/// result is discarded — the contract is "complete without panicking." A
/// malformed profile legitimately produces `Err` at any step; that is success.
fn exercise_full(bytes: &[u8]) {
    let Ok(profile) = Profile::open(bytes) else {
        return;
    };
    let _ = profile.header();

    // Read every tag both parsed and raw (mirrors ReadAllTags + ReadAllRAWTags).
    let sigs: Vec<Signature> = profile.tags().collect();
    for sig in &sigs {
        let _ = profile.read_tag(*sig);
        let _ = profile.read_tag_raw(*sig);
    }

    // Input/output/devicelink LUTs across all four intents (mirrors ReadAllLUTS).
    for intent in 0u32..=3 {
        let _ = read_input_lut(&profile, intent);
        let _ = read_output_lut(&profile, intent);
        let _ = read_devicelink_lut(&profile, intent);
    }

    // Black-point detection + TAC (mirrors the cmsDetect* calls).
    for ri in INTENTS {
        let _ = detect_black_point(&profile, ri);
        let _ = detect_destination_black_point(&profile, ri);
    }
    let _ = detect_tac(&profile);

    // PostScript CSA/CRD generation (mirrors GenerateCSA / GenerateCRD).
    for intent in 0u32..=3 {
        let _ = get_post_script_csa(&profile, intent, 0);
        let _ = get_post_script_crd(&profile, intent, 0);
    }
}

/// The hot subset for high-iteration mutation fuzzing: open, full tag decode
/// (parsed + raw), and one LUT build per direction. This reaches the
/// integer-overflow / CLUT-dimension / curve-parsing bounds logic — where the
/// panic risk concentrates — without paying for the per-intent sweep, TAC
/// sampling, black-point round-trips, and PostScript generation, which are slow,
/// lower-risk, and already covered by [`exercise_full`] over the curated corpus
/// and by the libFuzzer campaign in `fuzz/`.
fn exercise_fast(bytes: &[u8]) {
    let Ok(profile) = Profile::open(bytes) else {
        return;
    };
    let _ = profile.header();
    for sig in profile.tags().collect::<Vec<_>>() {
        let _ = profile.read_tag(sig);
        let _ = profile.read_tag_raw(sig);
    }
    let _ = read_input_lut(&profile, 0);
    let _ = read_output_lut(&profile, 0);
    let _ = read_devicelink_lut(&profile, 0);
}

/// Run `f(bytes)` and turn a panic into a test failure carrying enough context
/// to reproduce it, instead of an opaque abort somewhere inside the parser.
fn assert_no_panic(label: &str, bytes: &[u8], f: impl Fn(&[u8])) {
    let result = catch_unwind(AssertUnwindSafe(|| f(bytes)));
    if result.is_err() {
        let prefix: Vec<String> = bytes.iter().take(32).map(|b| format!("{b:02x}")).collect();
        panic!(
            "PANIC on malformed input [{label}] (len={}, first 32 bytes: {})\n\
             A panic here is a denial-of-service on the ICC-parse surface. The \
             parser must return Err on malformed input, never panic.",
            bytes.len(),
            prefix.join(" "),
        );
    }
}

// ---------------------------------------------------------------------------
// 1. lcms2's own malformed-ICC fixtures must not panic.
// ---------------------------------------------------------------------------

/// `bad.icc`, `bad_mpe.icc`, `toosmall.icc` ship in the lcms2 testbed precisely
/// because they exercise the parser's error paths (`CheckBadProfiles`,
/// `bad_mpe.icc` handling in `testcms2.c`). tintbox must survive them.
#[test]
fn lcms2_malformed_fixtures_do_not_panic() {
    for name in ["bad.icc", "bad_mpe.icc", "toosmall.icc"] {
        let bytes = read_testbed(name);
        assert_no_panic(name, &bytes, exercise_full);
    }
}

// ---------------------------------------------------------------------------
// 2. Hand-crafted CVE-shape headers reachable directly from Profile::open.
// ---------------------------------------------------------------------------

/// Build a minimal 128-byte ICC header plus a tag table of `entries`, where
/// each entry is `(signature, offset, size)`. Mirrors the on-disk layout
/// `Profile::open` parses, so we can aim malformed offsets/sizes/counts straight
/// at the bounds-checking code.
fn synthetic_profile(tag_count: u32, entries: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    // profile size (offset 0) — left as the true buffer length is filled later.
    buf[36..40].copy_from_slice(b"acsp"); // magic signature ('acsp')
    buf[16..20].copy_from_slice(b"RGB "); // data colour space
    buf[20..24].copy_from_slice(b"XYZ "); // PCS
    buf.extend_from_slice(&tag_count.to_be_bytes()); // tag count
    for (sig, off, size) in entries {
        buf.extend_from_slice(&sig.to_be_bytes());
        buf.extend_from_slice(&off.to_be_bytes());
        buf.extend_from_slice(&size.to_be_bytes());
    }
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_be_bytes());
    buf
}

#[test]
fn integer_overflow_shaped_headers_do_not_panic() {
    // CVE-2018-16435 / CVE-2026-41254 family: attacker-controlled counts and
    // offset+size pairs chosen to overflow a naive `offset + size` or
    // `count * stride` before the bounds check. In safe Rust these must surface
    // as Err (or a checked rejection), never a panic or a wild allocation.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // A tag count of 0xFFFF_FFFF: a naive reader multiplies by the 12-byte
        // stride and/or pre-allocates a vector of that many entries.
        ("huge_tag_count", synthetic_profile(0xFFFF_FFFF, &[])),
        // Tag count says 1 but the table is absent (truncated directory).
        ("count_without_table", synthetic_profile(1, &[])),
        // offset + size overflows u32 and points far past EOF.
        (
            "offset_size_overflow",
            synthetic_profile(
                1,
                &[(u32::from_be_bytes(*b"wtpt"), 0xFFFF_FFF0, 0x0000_0040)],
            ),
        ),
        // offset within header but size enormous.
        (
            "size_past_eof",
            synthetic_profile(1, &[(u32::from_be_bytes(*b"wtpt"), 128, 0xFFFF_FFFF)]),
        ),
        // offset past EOF, modest size.
        (
            "offset_past_eof",
            synthetic_profile(1, &[(u32::from_be_bytes(*b"A2B0"), 0x7FFF_FFFF, 16)]),
        ),
    ];
    for (label, bytes) in cases {
        assert_no_panic(label, &bytes, exercise_full);
    }
}

#[test]
fn truncated_and_garbage_inputs_do_not_panic() {
    // Empty, sub-header, header-only, and pure-garbage buffers.
    let garbage: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one_byte", vec![0x00]),
        ("sub_header", vec![0xAB; 64]),
        ("header_only_zeros", vec![0x00; 128]),
        ("acsp_then_nothing", {
            let mut v = vec![0u8; 132];
            v[36..40].copy_from_slice(b"acsp");
            v
        }),
        ("all_ff", vec![0xFF; 512]),
    ];
    for (label, bytes) in garbage {
        assert_no_panic(label, &bytes, exercise_full);
    }
}

// ---------------------------------------------------------------------------
// 3. Deterministic mutation fuzz over valid seeds (always-on, in-tree).
// ---------------------------------------------------------------------------

/// Tiny deterministic PRNG (xorshift64*) so any failure reproduces from the
/// fixed seed — no `rand` dependency, no run-to-run flakiness.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// Mutate a valid profile and confirm the decode surface never panics. Bit
/// flips and truncations walk the parser into partially-valid states — the most
/// productive way to reach deep bounds/overflow logic that pure garbage never
/// gets near (a totally random buffer is rejected at the magic check).
#[test]
fn mutated_valid_profiles_do_not_panic() {
    // Small/medium seeds keep this a fast always-on smoke layer; test3 still
    // carries CLUT/curve tags so the overflow-prone paths get exercised. The
    // exhaustive, coverage-guided campaign over large LUT profiles lives in
    // `crates/tintbox/fuzz/` (libFuzzer), not in this per-`cargo test` run.
    let seeds: Vec<Vec<u8>> = ["test5.icc", "crayons.icc", "test3.icc"]
        .iter()
        .map(|n| read_testbed(n))
        .collect();

    let mut rng = Rng(0x1CC_FACADE);
    // Fast by default so it runs every `cargo test`; CI / nightly can deepen the
    // pass with `TINTBOX_FUZZ_ITERS=50000 cargo test` without touching code.
    let iters: usize = std::env::var("TINTBOX_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    for i in 0..iters {
        let seed = &seeds[rng.below(seeds.len())];
        let mut buf = seed.clone();

        match rng.below(3) {
            // Truncate to a random prefix.
            0 => buf.truncate(rng.below(buf.len().max(1))),
            // Flip 1..=4 random bytes.
            1 => {
                for _ in 0..=rng.below(4) {
                    let idx = rng.below(buf.len().max(1));
                    if idx < buf.len() {
                        buf[idx] ^= (rng.next_u64() & 0xFF) as u8;
                    }
                }
            }
            // Corrupt a 4-byte big-endian field (a length/offset/count) in the
            // header or tag table — directly targets the size-arithmetic paths.
            _ => {
                if buf.len() >= 4 {
                    let idx = rng.below(buf.len() - 3);
                    let v = (rng.next_u64() as u32).to_be_bytes();
                    buf[idx..idx + 4].copy_from_slice(&v);
                }
            }
        }

        assert_no_panic(&format!("mutation iter={i}"), &buf, exercise_fast);
    }
}

// ---------------------------------------------------------------------------
// 4. Differential parity against the lcms2 oracle on VALID profiles.
// ---------------------------------------------------------------------------

/// On well-formed profiles tintbox must agree with lcms2: both accept, expose
/// the same tag set, and compute the same TAC. (Accept/reject parity is asserted
/// only here — on *malformed* input the two engines may legitimately draw the
/// strict/lenient line in different places, so the mutation tests above check
/// robustness, not agreement.)
#[test]
fn valid_profiles_match_lcms2_oracle() {
    let valid = [
        "crayons.icc",
        "ibm-t61.icc",
        "new.icc",
        "test1.icc",
        "test2.icc",
        "test3.icc",
        "test4.icc",
        "test5.icc",
    ];
    for name in valid {
        let bytes = read_testbed(name);

        let tb_ok = Profile::open(&bytes).is_ok();
        let oracle_ok = tintbox_oracle::open_succeeds(&bytes);
        assert_eq!(
            tb_ok, oracle_ok,
            "{name}: accept/reject divergence (tintbox={tb_ok}, lcms2={oracle_ok})"
        );
        if !tb_ok {
            continue;
        }

        // Tag set parity (compare sorted — tag-table order is not contractual).
        let profile = Profile::open(&bytes).unwrap();
        let mut tb_tags: Vec<u32> = profile.tags().map(|s| s.to_raw()).collect();
        tb_tags.sort_unstable();
        if let Some(mut oracle_tags) = tintbox_oracle::tag_signatures(&bytes) {
            oracle_tags.sort_unstable();
            assert_eq!(tb_tags, oracle_tags, "{name}: tag-signature set diverges");
        }

        // TAC parity. detect_tac is part of the bit-identity surface.
        let tb_tac = detect_tac(&profile);
        let oracle_tac = tintbox_oracle::detect_tac(&bytes);
        assert!(
            (tb_tac - oracle_tac).abs() < 1e-6 || (tb_tac.is_nan() && oracle_tac.is_nan()),
            "{name}: TAC diverges (tintbox={tb_tac}, lcms2={oracle_tac})"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Transform *evaluation* robustness (not just parsing).
// ---------------------------------------------------------------------------

/// Build a transform between the profile and sRGB in both directions and push a
/// small pixel buffer through, exercising the evaluation pipeline — input/output
/// curves, matrix, CLUT interpolation, PCS conversion, black-point compensation —
/// rather than stopping at the parse. Any `Err` is fine; the contract is no
/// panic / no hang. The deep, coverage-guided version is the `transform_profile`
/// cargo-fuzz target.
fn exercise_transform(bytes: &[u8]) {
    let Ok(profile) = Profile::open(bytes) else {
        return;
    };
    let (dev_fmt, dev_bpp) = match profile.header().color_space {
        ColorSpace::Gray => (TYPE_GRAY_8, 1usize),
        ColorSpace::Rgb => (TYPE_RGB_8, 3),
        ColorSpace::Cmyk => (TYPE_CMYK_8, 4),
        _ => return,
    };
    let srgb = build_srgb_profile();
    let Ok(rgb) = Profile::from_writable(&srgb) else {
        return;
    };

    const N: usize = 32;
    let intent = RenderingIntent::RelativeColorimetric;
    // Device -> sRGB (drives the profile's AToB / input curves / matrix / CLUT).
    if let Ok(x) =
        Transform::new_simple_with_formats(&profile, &rgb, intent, true, dev_fmt, TYPE_RGB_8)
    {
        let src = vec![0x80u8; N * dev_bpp];
        let mut dst = vec![0u8; N * 3];
        x.do_transform(&src, &mut dst, N);
    }
    // sRGB -> device (drives the profile's BToA / output curves).
    if let Ok(x) =
        Transform::new_simple_with_formats(&rgb, &profile, intent, true, TYPE_RGB_8, dev_fmt)
    {
        let src = vec![0x80u8; N * 3];
        let mut dst = vec![0u8; N * dev_bpp];
        x.do_transform(&src, &mut dst, N);
    }
}

#[test]
fn transform_eval_does_not_panic() {
    // Valid profiles actually build a transform, so this drives the real eval
    // pipeline end to end (test1/test2 carry CLUTs); mutations add adversarial
    // coverage of the build + eval path.
    for name in [
        "crayons.icc",
        "ibm-t61.icc",
        "new.icc",
        "test1.icc", // carries CLUTs — drives interpolation in eval
        "test3.icc",
        "test5.icc",
    ] {
        let bytes = read_testbed(name);
        assert_no_panic(&format!("transform {name}"), &bytes, exercise_transform);
    }

    let seeds: Vec<Vec<u8>> = ["crayons.icc", "test3.icc"]
        .iter()
        .map(|n| read_testbed(n))
        .collect();
    let mut rng = Rng(0xABCD_1234);
    let iters: usize = std::env::var("TINTBOX_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150);
    for i in 0..iters {
        let seed = &seeds[rng.below(seeds.len())];
        let mut buf = seed.clone();
        for _ in 0..=rng.below(4) {
            let idx = rng.below(buf.len().max(1));
            if idx < buf.len() {
                buf[idx] ^= (rng.next_u64() & 0xFF) as u8;
            }
        }
        assert_no_panic(
            &format!("transform mutation iter={i}"),
            &buf,
            exercise_transform,
        );
    }
}
