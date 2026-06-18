//! Coverage-guided fuzzing of the CGATS / IT8.7 parser — the tabular-color-data
//! surface (calibration targets, measurement files). In lcms2 this is the home
//! of CVE-2018-16435 (integer overflow on attacker-controlled field/set counts →
//! undersized allocation → heap overflow). In safe Rust the class degrades to a
//! panic or oversized allocation; this target hunts both.
//!
//! Seed from any IT8/CGATS sample (e.g. the `VALID_IT8` stream in
//! `tests/malformed_cgats.rs`).
#![no_main]

use libfuzzer_sys::fuzz_target;

use tintbox::cgats::Profile as Cgats;

fuzz_target!(|data: &[u8]| {
    let Ok(mut p) = Cgats::load_from_mem(data) else {
        return;
    };
    let tables = p.table_count().min(64);
    for t in 0..tables {
        let _ = p.set_table(t);
        let _ = p.sheet_type();

        let keys: Vec<String> = p.enum_properties().iter().map(|s| s.to_string()).collect();
        for k in &keys {
            let _ = p.get_property(k);
            let _ = p.get_property_dbl(k);
        }

        let n = p.num_samples().clamp(0, 4096);
        for c in 0..n {
            let _ = p.data_format(c);
        }
        for r in 0..256 {
            for c in 0..n.min(64) {
                let _ = p.get_data_rowcol(r, c);
                let _ = p.get_data_rowcol_dbl(r, c);
            }
        }
    }
});
