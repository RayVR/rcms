//! Structure-aware fuzzing of the packed-pixel transform path — the pack /
//! unpack / evaluate kernels (lcms2's `UnrollChunkyBytes` & friends, the
//! CVE-2025-29069 neighbourhood).
//!
//! Rather than throw raw bytes at `do_transform` (which would mostly produce
//! buffer-size contract violations — expected panics, not bugs), we use
//! `arbitrary` to pick a *valid* format pair and intent, then size the buffers
//! correctly and fuzz the pixel *contents*, the pixel count, and the format
//! selection. That drives arbitrary colour values through every packing variant
//! (alpha, 16-bit, channel layout) on well-formed buffers, where a panic would
//! be a genuine kernel bug.
//!
//! Scoped to the RGB family so both ends match the sRGB virtual profile; the
//! ICC-decode surface is covered by the `icc_profile` target.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use tintbox::format::decode::{TYPE_RGBA_8, TYPE_RGB_16, TYPE_RGB_8};
use tintbox::profile::virtuals::build_srgb_profile;
use tintbox::profile::{Profile, RenderingIntent};
use tintbox::transform::Transform;

/// (format code, bytes per pixel) for the RGB-family formats we fuzz.
const FORMATS: [(u32, usize); 3] = [(TYPE_RGB_8, 3), (TYPE_RGBA_8, 4), (TYPE_RGB_16, 6)];

const INTENTS: [RenderingIntent; 4] = [
    RenderingIntent::Perceptual,
    RenderingIntent::RelativeColorimetric,
    RenderingIntent::Saturation,
    RenderingIntent::AbsoluteColorimetric,
];

#[derive(Arbitrary, Debug)]
struct Input {
    in_fmt: u8,
    out_fmt: u8,
    intent: u8,
    bpc: bool,
    n_pixels: u16,
    data: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let (in_fmt, in_bpp) = FORMATS[input.in_fmt as usize % FORMATS.len()];
    let (out_fmt, out_bpp) = FORMATS[input.out_fmt as usize % FORMATS.len()];
    let intent = INTENTS[input.intent as usize % INTENTS.len()];

    // Bound pixel count so the fuzzer stays fast and allocations stay sane.
    let n = (input.n_pixels % 1024) as usize;

    let srgb = build_srgb_profile();
    let Ok(profile) = Profile::from_writable(&srgb) else {
        return;
    };

    let Ok(xform) =
        Transform::new_simple_with_formats(&profile, &profile, intent, input.bpc, in_fmt, out_fmt)
    else {
        return;
    };

    // Size buffers to the contract; fill input from the fuzz data (zero-padded).
    let mut src = vec![0u8; n * in_bpp];
    for (i, b) in src.iter_mut().enumerate() {
        if let Some(v) = input.data.get(i % input.data.len().max(1)) {
            *b = *v;
        }
    }
    let mut dst = vec![0u8; n * out_bpp];

    xform.do_transform(&src, &mut dst, n);
});
