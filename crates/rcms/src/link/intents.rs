//! The intent-driven profile-link chain (lcms2 `DefaultICCintents`,
//! `src/cmscnvrt.c:511-654`) and its helpers `ComputeConversion` (:353),
//! `AddConversion` (:421), `IsEmptyLayer` (:329), plus the `_cmsLinkProfiles`
//! BPC-array mutation (:1119-1135).
//!
//! This is the first end-to-end transform: given a list of profiles + per-link
//! intents/BPC/adaptation, it builds the un-optimized device-link
//! [`Pipeline`](crate::pipeline::Pipeline) by reading each profile's LUT
//! (`read_input_lut` / `read_output_lut` / `read_devicelink_lut`), inserting the
//! PCS-adaptation stages between profiles, and concatenating.
//!
//! Scope (slice-5 T2): the **relative-colorimetric, no-BPC, non-absolute** path
//! only. `compute_conversion` produces an identity matrix + zero offset (still
//! dividing the offset by `MAX_ENCODEABLE_XYZ` to match the C code path). The
//! absolute-colorimetric branch (`ComputeAbsoluteIntent`, T3) and the
//! black-point-compensation branch (`ComputeBlackPointCompensation`, T5) are
//! left as TODO hooks.

use crate::error::{Error, Result};
use crate::link::profile_lut::{read_devicelink_lut, read_input_lut, read_output_lut};
use crate::math::matrix::{Mat3, Vec3};
use crate::pipeline::{Pipeline, Stage};
use crate::profile::{ColorSpace, Profile, ProfileClass, RenderingIntent};

/// `MAX_ENCODEABLE_XYZ` (lcms2_internal.h:71): `1.0 + 32767.0/32768.0`. The
/// `ComputeConversion` offset divisor (cmscnvrt.c:412).
const MAX_ENCODEABLE_XYZ: f64 = 1.0 + 32767.0 / 32768.0;

/// `cmsGetEncodedICCversion >= 0x4000000` ⇒ V4 (cmscnvrt.c:1132). `Header.version`
/// already holds the validated/clamped encoded value (`cmsGetEncodedICCversion`).
const ICC_VERSION_V4: u32 = 0x0400_0000;

/// The 3x3 identity matrix (`_cmsMAT3identity`, cmsmtrx.c).
fn mat3_identity() -> Mat3 {
    Mat3([1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0])
}

/// lcms2 `_cmsLinkProfiles` BPC-array mutation (`cmscnvrt.c:1119-1135`), which
/// runs BEFORE the chain is built. Following Adobe's document: BPC does not apply
/// to absolute colorimetric (forced off), and is forced ON for V4 profiles in
/// perceptual and saturation.
///
/// `bpc` is mutated in place. `intents` and `profiles` must be the same length as
/// `bpc`; for each link `i`:
/// - if `intents[i] == AbsoluteColorimetric` → `bpc[i] = false`;
/// - if `intents[i] ∈ {Perceptual, Saturation}` and `profiles[i]` is V4
///   (encoded version `>= 0x4000000`) → `bpc[i] = true`.
pub fn link_bpc_mutation(intents: &[RenderingIntent], profiles: &[&Profile], bpc: &mut [bool]) {
    for i in 0..profiles.len() {
        if intents[i] == RenderingIntent::AbsoluteColorimetric {
            bpc[i] = false;
        }
        if intents[i] == RenderingIntent::Perceptual || intents[i] == RenderingIntent::Saturation {
            // Force BPC for V4 profiles in perceptual and saturation.
            if profiles[i].header().version >= ICC_VERSION_V4 {
                bpc[i] = true;
            }
        }
    }
}

/// lcms2 `IsEmptyLayer` (`cmscnvrt.c:329-348`): is the matrix/offset close enough
/// to identity that the conversion stage can be dropped? Returns `true` when
/// `Σ|m − I| + Σ|off| < 0.002`. (lcms2 also treats a NULL matrix as empty; here
/// the matrix is always present, so we only implement the numeric test.)
pub fn is_empty_layer(m: &Mat3, off: &Vec3) -> bool {
    let ident = mat3_identity();
    let mut diff = 0.0f64;

    // for (i=0; i < 3*3; i++) diff += fabs(m[i] - Ident[i]);
    for i in 0..9 {
        diff += (m.0[i] - ident.0[i]).abs();
    }
    // for (i=0; i < 3; i++) diff += fabs(off[i]);
    for i in 0..3 {
        diff += off.0[i].abs();
    }

    diff < 0.002
}

/// lcms2 `ComputeConversion` (`cmscnvrt.c:353-416`): compute the PCS-adaptation
/// matrix `m` and offset `off` between profile `i-1` (the current PCS) and
/// profile `i`.
///
/// **Slice-5 T2 scope:** only the NON-absolute, NON-BPC path is implemented — `m`
/// is the identity and `off` is zero. The absolute-colorimetric branch
/// (`ComputeAbsoluteIntent`, T3) and the BPC branch
/// (`ComputeBlackPointCompensation`, T5) are TODO hooks below. Regardless of the
/// branch, the C unconditionally divides every offset component by
/// `MAX_ENCODEABLE_XYZ` at the end (a no-op for the zero offset here, but the same
/// code path); we replicate that.
pub fn compute_conversion(
    _i: usize,
    _profiles: &[&Profile],
    intent: RenderingIntent,
    bpc: bool,
    _adaptation_state: f64,
) -> Result<(Mat3, Vec3)> {
    // m and off are set to identity and this is detected later on (cmscnvrt.c:364).
    let m = mat3_identity();
    let mut off = Vec3([0.0, 0.0, 0.0]);

    if intent == RenderingIntent::AbsoluteColorimetric {
        // TODO(T3): absolute colorimetric → ComputeAbsoluteIntent
        // (cmscnvrt.c:368-383, ComputeAbsoluteIntent :250-325). Reads media white
        // points + CHAD from profiles[i-1]/profiles[i] and builds the
        // chromatic-adaptation matrix. Not yet implemented; only the no-abs path
        // is exercised by T2.
        return Err(Error::Unsupported(
            "absolute-colorimetric conversion not implemented (T3)",
        ));
    } else if bpc {
        // TODO(T5): black-point compensation → cmsDetectBlackPoint /
        // cmsDetectDestinationBlackPoint + ComputeBlackPointCompensation
        // (cmscnvrt.c:387-399, :169-200). Not yet implemented; T2 runs with BPC
        // forced off.
        return Err(Error::Unsupported(
            "black-point-compensation conversion not implemented (T5)",
        ));
    }

    // Offset should be adjusted because of the encoding (cmscnvrt.c:402-413).
    // for (k=0; k < 3; k++) off[k] /= MAX_ENCODEABLE_XYZ;
    for k in 0..3 {
        off.0[k] /= MAX_ENCODEABLE_XYZ;
    }

    Ok((m, off))
}

/// lcms2 `AddConversion` (`cmscnvrt.c:421-487`): append the PCS-adaptation stage
/// for the `in_pcs` → `out_pcs` transition. The matrix `m`/offset `off` operate in
/// XYZ space; [`is_empty_layer`] decides whether the `Stage::Matrix` is dropped.
///
/// The four PCS cases:
/// - **XYZ → XYZ:** Matrix (iff not empty).
/// - **XYZ → Lab:** Matrix (iff not empty), then `Xyz2Lab`.
/// - **Lab → XYZ:** `Lab2Xyz`, then Matrix (iff not empty).
/// - **Lab → Lab:** iff not empty → `Lab2Xyz` + Matrix + `Xyz2Lab` (all three or
///   none).
/// - **default:** require `in_pcs == out_pcs`, else a colorspace-mismatch error.
pub fn add_conversion(
    result: &mut Pipeline,
    in_pcs: ColorSpace,
    out_pcs: ColorSpace,
    m: &Mat3,
    off: &Vec3,
) -> Result<()> {
    // The Matrix stage as cmsStageAllocMatrix(3, 3, m, off) builds it: 3 rows,
    // 3 cols, row-major matrix, 3-element offset.
    let matrix_stage = || Stage::Matrix {
        rows: 3,
        cols: 3,
        m: m.0.to_vec(),
        offset: Some(off.0.to_vec()),
    };

    match in_pcs {
        // Input profile operates in XYZ (cmscnvrt.c:429).
        ColorSpace::XYZ => match out_pcs {
            ColorSpace::XYZ => {
                // XYZ -> XYZ
                if !is_empty_layer(m, off) {
                    result.insert_stage_at_end(matrix_stage())?;
                }
            }
            ColorSpace::Lab => {
                // XYZ -> Lab
                if !is_empty_layer(m, off) {
                    result.insert_stage_at_end(matrix_stage())?;
                }
                result.insert_stage_at_end(Stage::Xyz2Lab)?;
            }
            _ => return Err(Error::Corrupt("ColorSpace mismatch")),
        },

        // Input profile operates in Lab (cmscnvrt.c:452).
        ColorSpace::Lab => match out_pcs {
            ColorSpace::XYZ => {
                // Lab -> XYZ
                result.insert_stage_at_end(Stage::Lab2Xyz)?;
                if !is_empty_layer(m, off) {
                    result.insert_stage_at_end(matrix_stage())?;
                }
            }
            ColorSpace::Lab => {
                // Lab -> Lab
                if !is_empty_layer(m, off) {
                    result.insert_stage_at_end(Stage::Lab2Xyz)?;
                    result.insert_stage_at_end(matrix_stage())?;
                    result.insert_stage_at_end(Stage::Xyz2Lab)?;
                }
            }
            _ => return Err(Error::Corrupt("ColorSpace mismatch")),
        },

        // On colorspaces other than PCS, check for same space (cmscnvrt.c:481).
        _ => {
            if in_pcs != out_pcs {
                return Err(Error::Corrupt("ColorSpace mismatch"));
            }
        }
    }

    Ok(())
}

/// lcms2 `ColorSpaceIsCompatible` (`cmscnvrt.c:491-506`): are `a` and `b`
/// interchangeable for the chain-junction check? Same space, MCH4↔CMYK, or
/// XYZ↔Lab.
fn color_space_is_compatible(a: ColorSpace, b: ColorSpace) -> bool {
    if a == b {
        return true;
    }
    // MCH4 substitution of CMYK.
    if a == ColorSpace::Mch4 && b == ColorSpace::Cmyk {
        return true;
    }
    if a == ColorSpace::Cmyk && b == ColorSpace::Mch4 {
        return true;
    }
    // XYZ/Lab are interchangeable (one computable from the other).
    if a == ColorSpace::XYZ && b == ColorSpace::Lab {
        return true;
    }
    if a == ColorSpace::Lab && b == ColorSpace::XYZ {
        return true;
    }
    false
}

/// lcms2 `cmsChannelsOfColorSpace` (`cmspcs.c:877-940`): the device channel count
/// of a color space, or `None` for an unrecognized space (the C `-1`).
fn channels_of_color_space(cs: ColorSpace) -> Option<usize> {
    use ColorSpace::*;
    Some(match cs {
        Mch1 | Color1 | Gray => 1,
        Mch2 | Color2 => 2,
        XYZ | Lab | Luv | YCbCr | Yxy | Rgb | Hsv | Hls | Cmy | Mch3 | Color3 => 3,
        LuvK | Cmyk | Mch4 | Color4 => 4,
        Mch5 | Color5 => 5,
        Mch6 | Color6 => 6,
        Mch7 | Color7 => 7,
        Mch8 | Color8 => 8,
        Mch9 | Color9 => 9,
        MchA | Color10 => 10,
        MchB | Color11 => 11,
        MchC | Color12 => 12,
        MchD | Color13 => 13,
        MchE | Color14 => 14,
        MchF | Color15 => 15,
        _ => return None,
    })
}

/// lcms2 `DefaultICCintents` (`cmscnvrt.c:511-651`): build the un-optimized
/// device-link [`Pipeline`] for the chain of `profiles` under the per-link
/// `intents`, `bpc`, and `adaptation` states.
///
/// The three-way conversion branch (spec §8.2), per profile `i`:
/// - **input leg** (`l_is_input`, a non-PCS connection): `read_input_lut` →
///   concat only (no conversion).
/// - **output leg** (a PCS connection, intent applies): `read_output_lut` →
///   `compute_conversion` → `add_conversion(Result, CurrentColorSpace,
///   ColorSpaceIn, m, off)` → concat.
/// - **devicelink / abstract leg** (link or abstract class): `read_devicelink_lut`;
///   conversion only if `Abstract && i > 0` (else identity m/off) →
///   `add_conversion` → concat.
///
/// After each profile, `CurrentColorSpace` advances to that profile's output
/// space. `flags` is currently unused (NOOPTIMIZE is the only slice-5 reference,
/// and NONEGATIVES clipping is out of T2 scope).
///
/// NOTE: the caller is expected to have already applied [`link_bpc_mutation`] to
/// `bpc` (lcms2 does this in `_cmsLinkProfiles` before invoking the handler).
pub fn default_icc_intents(
    profiles: &[&Profile],
    intents: &[RenderingIntent],
    bpc: &[bool],
    adaptation: &[f64],
    _flags: u32,
) -> Result<Pipeline> {
    let n_profiles = profiles.len();
    // For safety (cmscnvrt.c:529).
    if n_profiles == 0 {
        return Err(Error::Range);
    }
    assert_eq!(intents.len(), n_profiles);
    assert_eq!(bpc.len(), n_profiles);
    assert_eq!(adaptation.len(), n_profiles);

    // Allocate an empty LUT for holding the result. 0 channels means 'undefined'.
    let mut result = Pipeline::new(0, 0);

    // CurrentColorSpace = cmsGetColorSpace(hProfiles[0]) (cmscnvrt.c:535).
    let mut current_color_space = profiles[0].header().color_space;
    let mut color_space_out = ColorSpace::Lab; // initialized as in the C (:524).

    for i in 0..n_profiles {
        let profile = profiles[i];
        let class_sig = profile.header().device_class;
        let l_is_device_link =
            class_sig == ProfileClass::Link || class_sig == ProfileClass::Abstract;

        // First profile is used as input unless devicelink or abstract
        // (cmscnvrt.c:546-553).
        let l_is_input = if i == 0 && !l_is_device_link {
            true
        } else {
            // Else use the profile in the input direction if current space is not PCS.
            current_color_space != ColorSpace::XYZ && current_color_space != ColorSpace::Lab
        };

        let intent = intents[i];

        let (color_space_in, cs_out) = if l_is_input || l_is_device_link {
            (profile.header().color_space, profile.header().pcs)
        } else {
            (profile.header().pcs, profile.header().color_space)
        };
        color_space_out = cs_out;

        if !color_space_is_compatible(color_space_in, current_color_space) {
            return Err(Error::Corrupt("ColorSpace mismatch"));
        }

        // If devicelink is found, then no custom intent is allowed and we can read
        // the LUT to be applied. Settings don't apply here (cmscnvrt.c:576). We
        // also route a single named-color profile through here (nProfiles == 1).
        let single_named = class_sig == ProfileClass::NamedColor && n_profiles == 1;

        let lut = if l_is_device_link || single_named {
            let lut = read_devicelink_lut(profile, intent.to_raw())?;

            // What about abstract profiles? (cmscnvrt.c:583-589.)
            let (m, off) = if class_sig == ProfileClass::Abstract && i > 0 {
                compute_conversion(i, profiles, intent, bpc[i], adaptation[i])?
            } else {
                (mat3_identity(), Vec3([0.0, 0.0, 0.0]))
            };

            add_conversion(&mut result, current_color_space, color_space_in, &m, &off)?;
            lut
        } else if l_is_input {
            // Input direction means non-pcs connection, so proceed like devicelinks
            // (cmscnvrt.c:597-600). No conversion.
            read_input_lut(profile, intent.to_raw())?
        } else {
            // Output direction means PCS connection. Intent may apply here
            // (cmscnvrt.c:602-611).
            let lut = read_output_lut(profile, intent.to_raw())?;
            let (m, off) = compute_conversion(i, profiles, intent, bpc[i], adaptation[i])?;
            add_conversion(&mut result, current_color_space, color_space_in, &m, &off)?;
            lut
        };

        // Concatenate to the output LUT (cmscnvrt.c:616).
        result.concat(&lut)?;

        // Update current space (cmscnvrt.c:623).
        current_color_space = color_space_out;
    }

    // Final channel sanity guard: the chain's output width must match the device
    // channel count of the last profile's output space. lcms2 enforces this
    // implicitly through cmsPipelineCat/BlessLUT as stages are appended; we assert
    // it explicitly to catch a mis-built chain early. (NONEGATIVES clipping,
    // cmscnvrt.c:626-640, is out of T2 scope.)
    if let Some(n) = channels_of_color_space(color_space_out) {
        if result.output_channels != n {
            return Err(Error::Corrupt(
                "final pipeline output width does not match output color space channels",
            ));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- is_empty_layer (boundary 0.002) ------------------------------------

    #[test]
    fn is_empty_layer_identity_is_empty() {
        let m = mat3_identity();
        let off = Vec3([0.0, 0.0, 0.0]);
        assert!(is_empty_layer(&m, &off));
    }

    #[test]
    fn is_empty_layer_boundary() {
        // Sum of |m-I|+|off| just under 0.002 → empty; at/over → not empty.
        // Perturb a single matrix entry by exactly 0.0019 (< 0.002) → empty.
        let mut m = mat3_identity();
        m.0[0] = 1.0 + 0.0019;
        let off = Vec3([0.0, 0.0, 0.0]);
        assert!(is_empty_layer(&m, &off), "0.0019 < 0.002 ⇒ empty");

        // Exactly 0.002 → NOT < 0.002 ⇒ not empty.
        let mut m2 = mat3_identity();
        m2.0[0] = 1.0 + 0.002;
        assert!(
            !is_empty_layer(&m2, &off),
            "0.002 is not < 0.002 ⇒ not empty"
        );

        // Just over via offset: |off| = 0.0025 ⇒ not empty.
        let off2 = Vec3([0.0025, 0.0, 0.0]);
        assert!(!is_empty_layer(&mat3_identity(), &off2));
    }

    #[test]
    fn is_empty_layer_accumulates_across_entries() {
        // Several tiny perturbations summing to >= 0.002 ⇒ not empty.
        let mut m = mat3_identity();
        m.0[1] = 0.001;
        m.0[2] = 0.001;
        let off = Vec3([0.0005, 0.0, 0.0]);
        // 0.001 + 0.001 + 0.0005 = 0.0025 >= 0.002.
        assert!(!is_empty_layer(&m, &off));
    }

    // ---- add_conversion (each of the 4 PCS cases) ---------------------------

    fn ident_m_off() -> (Mat3, Vec3) {
        (mat3_identity(), Vec3([0.0, 0.0, 0.0]))
    }

    #[test]
    fn add_conversion_xyz_to_xyz_empty_inserts_nothing() {
        let (m, off) = ident_m_off();
        let mut p = Pipeline::new(3, 3);
        add_conversion(&mut p, ColorSpace::XYZ, ColorSpace::XYZ, &m, &off).unwrap();
        assert!(p.stages().is_empty(), "identity XYZ->XYZ adds no stage");
    }

    #[test]
    fn add_conversion_xyz_to_xyz_non_empty_inserts_matrix() {
        let mut m = mat3_identity();
        m.0[0] = 2.0; // clearly not empty
        let off = Vec3([0.0, 0.0, 0.0]);
        let mut p = Pipeline::new(3, 3);
        add_conversion(&mut p, ColorSpace::XYZ, ColorSpace::XYZ, &m, &off).unwrap();
        assert_eq!(p.stages().len(), 1);
        assert!(matches!(p.stages()[0], Stage::Matrix { .. }));
    }

    #[test]
    fn add_conversion_xyz_to_lab() {
        let (m, off) = ident_m_off();
        let mut p = Pipeline::new(3, 3);
        add_conversion(&mut p, ColorSpace::XYZ, ColorSpace::Lab, &m, &off).unwrap();
        // Identity matrix dropped; only Xyz2Lab remains.
        assert_eq!(p.stages().len(), 1);
        assert!(matches!(p.stages()[0], Stage::Xyz2Lab));

        // Non-empty: Matrix then Xyz2Lab.
        let mut m2 = mat3_identity();
        m2.0[4] = 0.5;
        let mut p2 = Pipeline::new(3, 3);
        add_conversion(&mut p2, ColorSpace::XYZ, ColorSpace::Lab, &m2, &off).unwrap();
        assert_eq!(p2.stages().len(), 2);
        assert!(matches!(p2.stages()[0], Stage::Matrix { .. }));
        assert!(matches!(p2.stages()[1], Stage::Xyz2Lab));
    }

    #[test]
    fn add_conversion_lab_to_xyz() {
        let (m, off) = ident_m_off();
        let mut p = Pipeline::new(3, 3);
        add_conversion(&mut p, ColorSpace::Lab, ColorSpace::XYZ, &m, &off).unwrap();
        // Identity matrix dropped; only Lab2Xyz remains.
        assert_eq!(p.stages().len(), 1);
        assert!(matches!(p.stages()[0], Stage::Lab2Xyz));

        // Non-empty: Lab2Xyz then Matrix.
        let mut m2 = mat3_identity();
        m2.0[8] = 0.5;
        let mut p2 = Pipeline::new(3, 3);
        add_conversion(&mut p2, ColorSpace::Lab, ColorSpace::XYZ, &m2, &off).unwrap();
        assert_eq!(p2.stages().len(), 2);
        assert!(matches!(p2.stages()[0], Stage::Lab2Xyz));
        assert!(matches!(p2.stages()[1], Stage::Matrix { .. }));
    }

    #[test]
    fn add_conversion_lab_to_lab() {
        let (m, off) = ident_m_off();
        let mut p = Pipeline::new(3, 3);
        add_conversion(&mut p, ColorSpace::Lab, ColorSpace::Lab, &m, &off).unwrap();
        // Identity ⇒ all three dropped.
        assert!(p.stages().is_empty());

        // Non-empty ⇒ Lab2Xyz + Matrix + Xyz2Lab.
        let mut m2 = mat3_identity();
        m2.0[0] = 1.5;
        let mut p2 = Pipeline::new(3, 3);
        add_conversion(&mut p2, ColorSpace::Lab, ColorSpace::Lab, &m2, &off).unwrap();
        assert_eq!(p2.stages().len(), 3);
        assert!(matches!(p2.stages()[0], Stage::Lab2Xyz));
        assert!(matches!(p2.stages()[1], Stage::Matrix { .. }));
        assert!(matches!(p2.stages()[2], Stage::Xyz2Lab));
    }

    #[test]
    fn add_conversion_default_same_space_ok_mismatch_err() {
        let (m, off) = ident_m_off();
        // Non-PCS same space → no stage, no error.
        let mut p = Pipeline::new(3, 3);
        add_conversion(&mut p, ColorSpace::Rgb, ColorSpace::Rgb, &m, &off).unwrap();
        assert!(p.stages().is_empty());

        // Non-PCS mismatch → error.
        let mut p2 = Pipeline::new(3, 3);
        let err = add_conversion(&mut p2, ColorSpace::Rgb, ColorSpace::Cmyk, &m, &off);
        assert!(err.is_err());
    }

    // ---- link_bpc_mutation --------------------------------------------------

    #[test]
    fn link_bpc_mutation_absolute_forces_off() {
        // Build a minimal V4 RGB profile from the testbed (crayons is V4).
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/Little-CMS/testbed/crayons.icc"
        ))
        .unwrap();
        let p = Profile::open(&bytes).unwrap();
        assert!(p.header().version >= ICC_VERSION_V4, "crayons is V4");
        let profiles = [&p, &p];

        // Absolute → forced off even when requested on.
        let mut bpc = [true, true];
        link_bpc_mutation(
            &[
                RenderingIntent::AbsoluteColorimetric,
                RenderingIntent::AbsoluteColorimetric,
            ],
            &profiles,
            &mut bpc,
        );
        assert_eq!(bpc, [false, false]);
    }

    #[test]
    fn link_bpc_mutation_v4_perceptual_forces_on() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/Little-CMS/testbed/crayons.icc"
        ))
        .unwrap();
        let p = Profile::open(&bytes).unwrap();
        let profiles = [&p, &p];

        // V4 perceptual/saturation → forced on even when requested off.
        let mut bpc = [false, false];
        link_bpc_mutation(
            &[RenderingIntent::Perceptual, RenderingIntent::Saturation],
            &profiles,
            &mut bpc,
        );
        assert_eq!(bpc, [true, true]);
    }

    #[test]
    fn link_bpc_mutation_v2_perceptual_unchanged() {
        // test5 is a V2 RGB display profile (ver 0x02100000 < 0x04000000).
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/Little-CMS/testbed/test5.icc"
        ))
        .unwrap();
        let p = Profile::open(&bytes).unwrap();
        assert!(p.header().version < ICC_VERSION_V4, "test5 is V2");
        let profiles = [&p, &p];

        // V2 perceptual → NOT forced (left as caller requested).
        let mut bpc = [false, true];
        link_bpc_mutation(
            &[RenderingIntent::Perceptual, RenderingIntent::Perceptual],
            &profiles,
            &mut bpc,
        );
        assert_eq!(bpc, [false, true]);

        // RelativeColorimetric never touches the flag.
        let mut bpc2 = [true, false];
        link_bpc_mutation(
            &[
                RenderingIntent::RelativeColorimetric,
                RenderingIntent::RelativeColorimetric,
            ],
            &profiles,
            &mut bpc2,
        );
        assert_eq!(bpc2, [true, false]);
    }

    // ---- compute_conversion (relative path) ---------------------------------

    #[test]
    fn compute_conversion_relative_is_identity() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/Little-CMS/testbed/crayons.icc"
        ))
        .unwrap();
        let p = Profile::open(&bytes).unwrap();
        let profiles = [&p, &p];
        let (m, off) = compute_conversion(
            1,
            &profiles,
            RenderingIntent::RelativeColorimetric,
            false,
            1.0,
        )
        .unwrap();
        assert_eq!(m, mat3_identity());
        // Zero offset divided by MAX_ENCODEABLE_XYZ is still zero.
        assert_eq!(off, Vec3([0.0, 0.0, 0.0]));
        // And the resulting layer is empty.
        assert!(is_empty_layer(&m, &off));
    }
}
