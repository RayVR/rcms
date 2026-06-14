//! The tone-curve tag-type readers, transcribed from lcms2 `src/cmstypes.c`.
//! Both `cmsSigCurveType` (`'curv'`) and `cmsSigParametricCurveType` (`'para'`)
//! decode to a `cmsToneCurve`, modelled here as [`crate::curve::ToneCurve`] and
//! wrapped in [`Tag::Curve`]. Each reader takes the positioned reader `r`
//! (already past the 8-byte type base) and `size` = `TagSize - 8` (the byte
//! count the C handler receives as `SizeOfTag`, unused by these readers).

use crate::curve::{build_gamma, build_parametric, build_tabulated_16};
use crate::error::{Error, Result};
use crate::fixed::U8Fixed8;
use crate::io::ProfileReader;
use crate::profile::tag::Tag;

/// `Type_Curve_Read` (`cmstypes.c:1333`). Read `Count` (u32):
/// - `Count == 0`: a linear curve — lcms2 `cmsBuildParametricToneCurve(1, {1.0})`,
///   i.e. [`build_gamma`] with gamma 1.0.
/// - `Count == 1`: a single gamma exponent stored as a `cmsU8Fixed8Number` (u16)
///   decoded via `_cms8Fixed8toDouble`, then [`build_gamma`].
/// - `Count > 1`: a 16-bit tabulated curve of `Count` entries (lcms2 caps at
///   `0x7FFF` to reject hostile sizes), read as a big-endian u16 array.
pub fn read_curve<R: ProfileReader>(r: &mut R, _size: u32) -> Result<Tag> {
    let count = r.read_u32()?;
    let curve = match count {
        0 => build_gamma(1.0),
        1 => {
            let fixed = U8Fixed8::from_raw(r.read_u16()?);
            build_gamma(fixed.to_f64())
        }
        _ => {
            // lcms2: "This is to prevent bad guys for doing bad things".
            if count > 0x7FFF {
                return Err(Error::Corrupt("curve entry count exceeds 0x7FFF"));
            }
            let table = r.read_u16_array(count as usize)?;
            build_tabulated_16(&table)
        }
    };
    Ok(Tag::Curve(curve))
}

/// lcms2 `ParamsByType` (`cmstypes.c:1453`): the coefficient count for each ICC
/// parametric curve type 0..=4 (one segment each).
const PARAMS_BY_TYPE: [usize; 5] = [1, 3, 4, 5, 7];

/// `Type_ParametricCurve_Read` (`cmstypes.c:1451`). Read the ICC parametric curve
/// `Type` (u16), skip a reserved u16, then read `PARAMS_BY_TYPE[Type]` parameters
/// each as a 15.16 fixed (`_cmsRead15Fixed16Number` → f64). lcms2 rejects
/// `Type > 4`. The lcms2 curve type is the ICC type plus one
/// (`cmsBuildParametricToneCurve(Type + 1, Params)`).
pub fn read_parametric_curve<R: ProfileReader>(r: &mut R, _size: u32) -> Result<Tag> {
    let icc_type = r.read_u16()?;
    let _reserved = r.read_u16()?;

    if icc_type > 4 {
        return Err(Error::Corrupt("unknown parametric curve type"));
    }

    let n = PARAMS_BY_TYPE[icc_type as usize];
    let mut params = [0.0f64; 10];
    for slot in params.iter_mut().take(n) {
        *slot = r.read_s15f16()?.to_f64();
    }

    // lcms2 curve type = ICC type + 1; build_parametric reads params[0..n].
    let curve = build_parametric(icc_type as i32 + 1, &params)
        .ok_or(Error::Corrupt("parametric curve build failed"))?;
    Ok(Tag::Curve(curve))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MemReader;

    /// `Count == 0` → an identity (gamma-1.0) linear curve, exactly
    /// `cmsBuildParametricToneCurve(1, {1.0})` == [`build_gamma(1.0)`].
    #[test]
    fn curve_count0_is_identity() {
        let body = 0u32.to_be_bytes(); // Count = 0
        let mut r = MemReader::new(&body);
        match read_curve(&mut r, body.len() as u32).unwrap() {
            Tag::Curve(c) => assert_eq!(c, build_gamma(1.0)),
            other => panic!("expected Curve, got {other:?}"),
        }
    }

    /// `Count == 1` → a single gamma exponent stored as a `cmsU8Fixed8Number`.
    /// `0x0240` = 2.25 (576 / 256), so the curve is `build_gamma(2.25)`.
    #[test]
    fn curve_count1_single_gamma() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // Count = 1
        body.extend_from_slice(&0x0240u16.to_be_bytes()); // 8.8 fixed = 2.25
        let mut r = MemReader::new(&body);
        match read_curve(&mut r, body.len() as u32).unwrap() {
            Tag::Curve(c) => {
                assert_eq!(c, build_gamma(2.25));
                // Sanity: the stored exponent decodes via _cms8Fixed8toDouble.
                assert_eq!(U8Fixed8::from_raw(0x0240).to_f64(), 2.25);
            }
            other => panic!("expected Curve, got {other:?}"),
        }
    }

    /// `Count > 1` → a 16-bit tabulated curve copying the on-disk samples verbatim.
    #[test]
    fn curve_count_n_tabulated() {
        let table: [u16; 4] = [0, 0x5555, 0xAAAA, 0xFFFF];
        let mut body = Vec::new();
        body.extend_from_slice(&(table.len() as u32).to_be_bytes());
        for v in table {
            body.extend_from_slice(&v.to_be_bytes());
        }
        let mut r = MemReader::new(&body);
        match read_curve(&mut r, body.len() as u32).unwrap() {
            Tag::Curve(c) => assert_eq!(c, build_tabulated_16(&table)),
            other => panic!("expected Curve, got {other:?}"),
        }
    }

    /// `Count > 0x7FFF` is rejected (lcms2's hostile-size guard).
    #[test]
    fn curve_count_too_large_rejected() {
        let body = 0x8000u32.to_be_bytes();
        let mut r = MemReader::new(&body);
        assert!(matches!(
            read_curve(&mut r, body.len() as u32),
            Err(Error::Corrupt(_))
        ));
    }

    /// `para` type 0 (ICC) → lcms2 type 1, one s15Fixed16 param. `0x0002_0000` =
    /// 2.0, so this is `build_parametric(1, {2.0})`.
    #[test]
    fn parametric_type0_gamma() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // ICC Type 0
        body.extend_from_slice(&0u16.to_be_bytes()); // reserved
        body.extend_from_slice(&0x0002_0000u32.to_be_bytes()); // gamma = 2.0
        let mut r = MemReader::new(&body);
        match read_parametric_curve(&mut r, body.len() as u32).unwrap() {
            Tag::Curve(c) => assert_eq!(c, build_parametric(1, &[2.0]).unwrap()),
            other => panic!("expected Curve, got {other:?}"),
        }
    }

    /// `para` type 3 (ICC) → lcms2 type 4, four s15Fixed16 params (a sRGB-like set).
    #[test]
    fn parametric_type3_params() {
        // ParamsByType[3] = 5 params; values picked to be exact in 15.16.
        let raws: [u32; 5] = [
            0x0002_0000, // 2.0
            0x0000_8000, // 0.5
            0x0000_4000, // 0.25
            0x0000_2000, // 0.125
            0x0000_1000, // 0.0625
        ];
        let mut body = Vec::new();
        body.extend_from_slice(&3u16.to_be_bytes()); // ICC Type 3
        body.extend_from_slice(&0u16.to_be_bytes()); // reserved
        for raw in raws {
            body.extend_from_slice(&raw.to_be_bytes());
        }
        let mut r = MemReader::new(&body);
        let expected = build_parametric(4, &[2.0, 0.5, 0.25, 0.125, 0.0625]).unwrap();
        match read_parametric_curve(&mut r, body.len() as u32).unwrap() {
            Tag::Curve(c) => assert_eq!(c, expected),
            other => panic!("expected Curve, got {other:?}"),
        }
    }

    /// ICC parametric type > 4 is rejected (lcms2's unknown-extension guard).
    #[test]
    fn parametric_unknown_type_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_be_bytes()); // ICC Type 5 (> 4)
        body.extend_from_slice(&0u16.to_be_bytes()); // reserved
        let mut r = MemReader::new(&body);
        assert!(matches!(
            read_parametric_curve(&mut r, body.len() as u32),
            Err(Error::Corrupt(_))
        ));
    }
}
