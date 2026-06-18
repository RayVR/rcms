//! End-to-end transform fuzzing on an **attacker-controlled profile**.
//!
//! This is the surface the other targets stop short of. `icc_profile` parses
//! tags and builds LUTs but never evaluates them; `transform_packed` drives only
//! the trusted sRGB virtual profile. So the *evaluation* pipeline — input curves,
//! matrix, CLUT interpolation, PCS conversion, black-point compensation, and
//! per-intent dispatch — is never exercised with adversarial profile internals.
//! `cmsDoTransform` on a crafted profile is a primary lcms2 surface; this drives
//! it in **both** directions (the profile's AToB *and* BToA) across every intent
//! and BPC setting.
//!
//! Safe Rust rules out the memory-corruption failure mode; what this hunts is a
//! panic (an `unwrap`/index/cast in the eval kernels), an unbounded loop/hang
//! (e.g. a degenerate curve inversion), or a wild allocation.
//!
//! Seed from `vendor/Little-CMS/testbed/*.icc` — mutations of real profiles
//! reach the transform-build path far more often than random bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

use tintbox::format::decode::{TYPE_CMYK_8, TYPE_GRAY_8, TYPE_RGB_8};
use tintbox::profile::virtuals::build_srgb_profile;
use tintbox::profile::{ColorSpace, Profile, RenderingIntent};
use tintbox::transform::Transform;

const INTENTS: [RenderingIntent; 4] = [
    RenderingIntent::Perceptual,
    RenderingIntent::RelativeColorimetric,
    RenderingIntent::Saturation,
    RenderingIntent::AbsoluteColorimetric,
];

/// A packed 8-bit format + its bytes-per-pixel for the profile's device space.
/// Returns `None` for spaces we don't pack here (the transform build would just
/// reject a mismatched format anyway).
fn device_format(space: ColorSpace) -> Option<(u32, usize)> {
    match space {
        ColorSpace::Gray => Some((TYPE_GRAY_8, 1)),
        ColorSpace::Rgb => Some((TYPE_RGB_8, 3)),
        ColorSpace::Cmyk => Some((TYPE_CMYK_8, 4)),
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(profile) = Profile::open(data) else {
        return;
    };
    let Some((dev_fmt, dev_bpp)) = device_format(profile.header().color_space) else {
        return;
    };

    let srgb = build_srgb_profile();
    let Ok(rgb) = Profile::from_writable(&srgb) else {
        return;
    };

    const N: usize = 64;
    for intent in INTENTS {
        for bpc in [false, true] {
            // Fuzzed profile -> sRGB: drives its AToB / input curves / matrix / CLUT.
            if let Ok(x) =
                Transform::new_simple_with_formats(&profile, &rgb, intent, bpc, dev_fmt, TYPE_RGB_8)
            {
                let src = vec![0x80u8; N * dev_bpp];
                let mut dst = vec![0u8; N * 3];
                x.do_transform(&src, &mut dst, N);
            }
            // sRGB -> fuzzed profile: drives its BToA / output curves.
            if let Ok(x) =
                Transform::new_simple_with_formats(&rgb, &profile, intent, bpc, TYPE_RGB_8, dev_fmt)
            {
                let src = vec![0x80u8; N * 3];
                let mut dst = vec![0u8; N * dev_bpp];
                x.do_transform(&src, &mut dst, N);
            }
        }
    }
});
