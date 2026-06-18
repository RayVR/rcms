//! Tone-curve build / evaluate / invert fuzzing.
//!
//! A profile's `para` (parametric) and `curv` tags carry the curve *type* and
//! *coefficients* verbatim, so building a curve, evaluating it, and — for the
//! BToA direction — inverting it all run on attacker-controlled numbers. The
//! risk surface is numeric: `pow` of a negative base, `log`/division by zero,
//! NaN/inf coefficients, and the inversion search over a degenerate
//! (non-monotonic, flat, or spiky) curve. In safe Rust the failure mode is a
//! panic or a hang (a non-terminating inversion), not corruption — this hunts
//! both.
//!
//! lcms2's `smooth2`/gamma-estimation neighbourhood (CVE-2025-29070) lives here.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use tintbox::curve::{build_parametric, eval_parametric, reverse_tone_curve};

#[derive(Arbitrary, Debug)]
struct Input {
    curve_type: i32,
    params: [f64; 10],
    sample: f32,
}

fuzz_target!(|input: Input| {
    // Direct parametric evaluation (lcms2 `cmsEvalToneCurveFloat` on a `para`).
    let _ = eval_parametric(input.curve_type, &input.params, input.sample as f64);

    // Build -> evaluate (float + 16-bit) -> invert -> evaluate the inverse: the
    // path a transform walks when a profile's parametric curve must be reversed.
    if let Some(curve) = build_parametric(input.curve_type, &input.params) {
        let _ = curve.eval_float(input.sample);
        let v16 = (input.sample.clamp(0.0, 1.0) * 65535.0) as u16;
        let _ = curve.eval_16(v16);
        let inverse = reverse_tone_curve(&curve);
        let _ = inverse.eval_float(input.sample);
    }
});
