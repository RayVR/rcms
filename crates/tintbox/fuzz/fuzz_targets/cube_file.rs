//! Coverage-guided fuzzing of the `.cube` (Iridas/Adobe 3D-LUT) → RGB
//! device-link parser/builder. The tabular-color-data integer-overflow surface
//! (lcms2 `ParseCube`, CVE-2026-42798) — bounded here by the 2.19.1 grid cap.
//! In safe Rust the residual is a panic or hang on malformed input; this hunts
//! both. Seed from any `.cube` file.
#![no_main]

use libfuzzer_sys::fuzz_target;

use tintbox::cgats::create_devicelink_from_cube_mem;

fuzz_target!(|data: &[u8]| {
    let _ = create_devicelink_from_cube_mem(data);
});
