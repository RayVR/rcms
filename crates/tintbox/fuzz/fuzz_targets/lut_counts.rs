//! Structure-aware fuzzing of the mft1/mft2 (LUT8/LUT16) channel- and
//! dimension-count validation — the byte class the 16-input-channel CLUT panic
//! lived in. Builds tag bodies with arbitrary channel/grid counts and runs the
//! readers directly. They must reject bad counts cleanly, never panic (and never
//! build a CLUT the interpolator can't handle).
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use tintbox::io::MemReader;
use tintbox::profile::types::lut::{read_lut16, read_lut8};

#[derive(Arbitrary, Debug)]
struct Input {
    is_lut16: bool,
    in_chan: u8,
    out_chan: u8,
    clut_points: u8,
    /// The rest of the tag body (matrix, curve tables, entry counts, CLUT data)
    /// — arbitrary, so the count fields read from here are fuzzed too.
    body: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // mft body layout: in_chan, out_chan, clut_points, pad, then the rest.
    let mut bytes = vec![input.in_chan, input.out_chan, input.clut_points, 0];
    bytes.extend_from_slice(&input.body);
    let mut r = MemReader::new(&bytes);
    let len = bytes.len() as u32;
    if input.is_lut16 {
        let _ = read_lut16(&mut r, len);
    } else {
        let _ = read_lut8(&mut r, len);
    }
});
