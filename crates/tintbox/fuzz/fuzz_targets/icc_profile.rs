//! Coverage-guided fuzzing of the ICC-profile decode surface.
//!
//! Mirrors lcms2's own libFuzzer entry (`Little-CMS/fuzzers/fuzzers.c`): open
//! from memory, read every tag (parsed + raw), build input/output/devicelink
//! LUTs across all four intents, detect black point and TAC, and generate
//! PostScript CSA/CRD. tintbox is `#![forbid(unsafe_code)]`, so a finding here
//! is a panic / unbounded allocation / hang, never memory corruption.
//!
//! Seed this from real profiles: `vendor/Little-CMS/testbed/*.icc`.
#![no_main]

use libfuzzer_sys::fuzz_target;

use tintbox::gamut::detect_tac;
use tintbox::link::black_point::{detect_black_point, detect_destination_black_point};
use tintbox::link::{read_devicelink_lut, read_input_lut, read_output_lut};
use tintbox::profile::{Profile, RenderingIntent};
use tintbox::ps::{get_post_script_crd, get_post_script_csa};
use tintbox::sig::Signature;

const INTENTS: [RenderingIntent; 4] = [
    RenderingIntent::Perceptual,
    RenderingIntent::RelativeColorimetric,
    RenderingIntent::Saturation,
    RenderingIntent::AbsoluteColorimetric,
];

fuzz_target!(|data: &[u8]| {
    let Ok(profile) = Profile::open(data) else {
        return;
    };
    let _ = profile.header();

    let sigs: Vec<Signature> = profile.tags().collect();
    for sig in &sigs {
        let _ = profile.read_tag(*sig);
        let _ = profile.read_tag_raw(*sig);
    }

    for intent in 0u32..=3 {
        let _ = read_input_lut(&profile, intent);
        let _ = read_output_lut(&profile, intent);
        let _ = read_devicelink_lut(&profile, intent);
    }

    for ri in INTENTS {
        let _ = detect_black_point(&profile, ri);
        let _ = detect_destination_black_point(&profile, ri);
    }
    let _ = detect_tac(&profile);

    for intent in 0u32..=3 {
        let _ = get_post_script_csa(&profile, intent, 0);
        let _ = get_post_script_crd(&profile, intent, 0);
    }
});
