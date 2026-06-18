//! Differential fuzzing: tintbox vs. the `cc`-built lcms2 oracle on the same
//! bytes. This is the target lcms2's own fuzzer cannot be — it only checks "did
//! not crash." Here we additionally check that tintbox **agrees with lcms2**:
//!
//!  - same accept/reject decision on the profile,
//!  - same tag-signature set,
//!  - same detected TAC,
//!
//! which is what turns tintbox's "bit-identical to lcms2" claim from
//! self-attested into continuously demonstrated. Any divergence is a finding;
//! so is any tintbox panic.
//!
//! Note: accept/reject parity on heavily-malformed input is the interesting and
//! occasionally-fragile part — the two engines may draw the strict/lenient line
//! differently. If real corpora surface benign divergences there, narrow the
//! assertion to "tintbox accepts ⇒ lcms2 accepts" rather than dropping it.
#![no_main]

use libfuzzer_sys::fuzz_target;

use tintbox::gamut::detect_tac;
use tintbox::profile::Profile;

fuzz_target!(|data: &[u8]| {
    let tb_ok = Profile::open(data).is_ok();
    let oracle_ok = tintbox_oracle::open_succeeds(data);
    assert_eq!(
        tb_ok, oracle_ok,
        "accept/reject divergence: tintbox={tb_ok} lcms2={oracle_ok}"
    );
    if !tb_ok {
        return;
    }

    let profile = Profile::open(data).expect("just checked Ok");

    // Tag-signature set parity (order is not contractual; compare sorted).
    let mut tb_tags: Vec<u32> = profile.tags().map(|s| s.to_raw()).collect();
    tb_tags.sort_unstable();
    if let Some(mut oracle_tags) = tintbox_oracle::tag_signatures(data) {
        oracle_tags.sort_unstable();
        assert_eq!(tb_tags, oracle_tags, "tag-signature set diverges");
    }

    // TAC parity (part of the bit-identity surface).
    let tb_tac = detect_tac(&profile);
    let oracle_tac = tintbox_oracle::detect_tac(data);
    assert!(
        (tb_tac - oracle_tac).abs() < 1e-6 || (tb_tac.is_nan() && oracle_tac.is_nan()),
        "TAC diverges: tintbox={tb_tac} lcms2={oracle_tac}"
    );
});
