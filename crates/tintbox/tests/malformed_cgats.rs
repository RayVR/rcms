//! Untrusted-input robustness for the CGATS / IT8.7 parser
//! (`tintbox::cgats::Profile::load_from_mem`).
//!
//! This is the tabular-color-data attack surface: calibration targets, IT8/CGATS
//! measurement files, and the like, loaded from user-supplied data. In lcms2 it
//! is the home of the classic integer-overflow → undersized-allocation →
//! heap-overflow bug (CVE-2018-16435, `AllocateDataSet`/`SetData` in
//! `cmscgats.c`), where attacker-controlled `NUMBER_OF_FIELDS` / `NUMBER_OF_SETS`
//! multiply past `SIZE_MAX` before the allocation.
//!
//! In `#![forbid(unsafe_code)]` tintbox that whole class cannot corrupt memory —
//! it degrades to a panic (overflow/index/`unwrap`) or an oversized allocation
//! attempt. Both are denial-of-service in a server-side preflight pipeline, so
//! the contract enforced here is: **malformed IT8 input returns `Err` or parses
//! to a walkable-but-bounded table — never a panic.**

use std::panic::{catch_unwind, AssertUnwindSafe};

use tintbox::cgats::Profile as Cgats;

/// A representative well-formed IT8 stream: header properties, a DATA_FORMAT,
/// and a BEGIN_DATA..END_DATA block. Used as the mutation seed.
const VALID_IT8: &str = "IT8.7/2\n\
DESCRIPTOR\t\"robustness seed\"\n\
ORIGINATOR\t\"tintbox\"\n\
KEYWORD\t\"SAMPLE_ID\"\n\
NUMBER_OF_FIELDS\t4\n\
BEGIN_DATA_FORMAT\n\
SAMPLE_ID\tRGB_R\tRGB_G\tRGB_B\n\
END_DATA_FORMAT\n\
NUMBER_OF_SETS\t2\n\
BEGIN_DATA\n\
1\t10.0\t20.0\t30.0\n\
2\t40.0\t50.0\t60.0\n\
END_DATA\n";

/// Load and fully walk the table, mirroring what a consumer extracting an IT8
/// does. Loop bounds are clamped so that an attacker-controlled huge count
/// reported by the parser can't hang the *test* — the library not panicking is
/// what's under examination, not whether a naive consumer would loop forever.
fn exercise(bytes: &[u8]) {
    let Ok(mut p) = Cgats::load_from_mem(bytes) else {
        return;
    };
    let tables = p.table_count().min(64);
    for t in 0..tables {
        let _ = p.set_table(t);
        let _ = p.sheet_type();

        // Collect property keys to owned strings so the immutable borrow ends
        // before the next mutable `set_table`.
        let keys: Vec<String> = p.enum_properties().iter().map(|s| s.to_string()).collect();
        for k in &keys {
            let _ = p.get_property(k);
            let _ = p.get_property_dbl(k);
        }

        let n = p.num_samples().clamp(0, 4096);
        for c in 0..n {
            let _ = p.data_format(c);
        }
        // Probe a bounded data grid; out-of-range indices return None safely.
        for r in 0..256 {
            for c in 0..n.min(64) {
                let _ = p.get_data_rowcol(r, c);
                let _ = p.get_data_rowcol_dbl(r, c);
            }
        }
    }
}

fn assert_no_panic(label: &str, bytes: &[u8]) {
    let result = catch_unwind(AssertUnwindSafe(|| exercise(bytes)));
    assert!(
        result.is_ok(),
        "PANIC on malformed IT8 input [{label}] (len={}). The CGATS parser must \
         return Err on malformed input, never panic.",
        bytes.len(),
    );
}

#[test]
fn integer_overflow_shaped_it8_do_not_panic() {
    // The CVE-2018-16435 shape: attacker-controlled field/set counts that a
    // naive parser multiplies into an allocation size.
    let cases: Vec<(&str, String)> = vec![
        (
            "huge_number_of_fields",
            "IT8.7/2\nNUMBER_OF_FIELDS\t4294967295\nBEGIN_DATA_FORMAT\nSAMPLE_ID\n\
             END_DATA_FORMAT\nNUMBER_OF_SETS\t1\nBEGIN_DATA\n1\nEND_DATA\n"
                .to_string(),
        ),
        (
            "huge_number_of_sets",
            "IT8.7/2\nNUMBER_OF_FIELDS\t1\nBEGIN_DATA_FORMAT\nSAMPLE_ID\nEND_DATA_FORMAT\n\
             NUMBER_OF_SETS\t4294967295\nBEGIN_DATA\n1\nEND_DATA\n"
                .to_string(),
        ),
        (
            "negative_counts",
            "IT8.7/2\nNUMBER_OF_FIELDS\t-1\nNUMBER_OF_SETS\t-99999\nBEGIN_DATA_FORMAT\n\
             SAMPLE_ID\nEND_DATA_FORMAT\nBEGIN_DATA\n1\nEND_DATA\n"
                .to_string(),
        ),
        (
            "fields_count_mismatch",
            // Declares 4 fields but lists 1; declares 1000 sets but lists none.
            "IT8.7/2\nNUMBER_OF_FIELDS\t4\nBEGIN_DATA_FORMAT\nSAMPLE_ID\nEND_DATA_FORMAT\n\
             NUMBER_OF_SETS\t1000\nBEGIN_DATA\nEND_DATA\n"
                .to_string(),
        ),
        (
            "unterminated_data",
            "IT8.7/2\nNUMBER_OF_FIELDS\t1\nBEGIN_DATA_FORMAT\nSAMPLE_ID\nEND_DATA_FORMAT\n\
             NUMBER_OF_SETS\t2\nBEGIN_DATA\n1\n"
                .to_string(),
        ),
    ];
    for (label, text) in cases {
        assert_no_panic(label, text.as_bytes());
    }
}

#[test]
fn truncated_and_garbage_it8_do_not_panic() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("nul_bytes", vec![0u8; 256]),
        ("binary_garbage", (0u8..=255).cycle().take(1024).collect()),
        ("header_only", b"IT8.7/2\n".to_vec()),
        (
            "begin_without_end",
            b"IT8.7/2\nBEGIN_DATA\n1 2 3\n".to_vec(),
        ),
    ];
    for (label, bytes) in cases {
        assert_no_panic(label, &bytes);
    }

    // Every prefix of a valid stream — truncation at each byte boundary.
    let valid = VALID_IT8.as_bytes();
    for cut in 0..valid.len() {
        assert_no_panic(&format!("truncated@{cut}"), &valid[..cut]);
    }
}

/// Tiny deterministic xorshift PRNG — reproducible failures, no `rand` dep.
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

#[test]
fn mutated_valid_it8_do_not_panic() {
    let seed = VALID_IT8.as_bytes();
    let mut rng = Rng(0x17_C0FFEE);
    let iters: usize = std::env::var("TINTBOX_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    for i in 0..iters {
        let mut buf = seed.to_vec();
        match rng.below(3) {
            0 => buf.truncate(rng.below(buf.len().max(1))),
            1 => {
                for _ in 0..=rng.below(4) {
                    let idx = rng.below(buf.len().max(1));
                    if idx < buf.len() {
                        buf[idx] ^= (rng.next_u64() & 0xFF) as u8;
                    }
                }
            }
            // Splice a long ASCII-digit run in — pushes parsed numeric fields
            // toward overflow without breaking the surrounding structure.
            _ => {
                let idx = rng.below(buf.len().max(1));
                let digits = vec![b'9'; 1 + rng.below(40)];
                buf.splice(idx..idx, digits);
            }
        }
        assert_no_panic(&format!("mutation iter={i}"), &buf);
    }
}
