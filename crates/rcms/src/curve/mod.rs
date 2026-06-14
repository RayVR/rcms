//! Tone curves (lcms2 `cmsToneCurve`, cmsgamma.c).
//!
//! A tone curve is described by zero or more *curve segments* plus a
//! limited-precision 16-bit approximation table. A segment is either *sampled*
//! (`seg_type == 0`, evaluated by table interpolation over `sampled`) or
//! *parametric* (`seg_type != 0`, evaluated by [`eval_parametric`] from the ICC
//! parametric function family).
//!
//! This task lands the data model plus the parametric evaluator; constructors
//! and full evaluation (table build / interpolation) arrive in a later task.

mod parametric;

pub use parametric::eval_parametric;

/// One segment of a segmented tone curve (lcms2 `cmsCurveSegment`).
///
/// `seg_type == 0` marks a *sampled* segment: it carries `sampled` points
/// interpolated over `[x0, x1]`. A nonzero `seg_type` is an ICC parametric
/// function (positive forward types 1..=8/108/109 and their negative inverses);
/// `params` holds its coefficients (each type reads `params[0..n]`).
#[derive(Clone, Debug, PartialEq)]
pub struct CurveSegment {
    /// Lower bound of the segment's domain (exclusive in lcms2's `EvalSegmentedFn`).
    pub x0: f32,
    /// Upper bound of the segment's domain (inclusive in lcms2's `EvalSegmentedFn`).
    pub x1: f32,
    /// ICC parametric function type, or `0` for a sampled segment.
    pub seg_type: i32,
    /// Parametric coefficients (only `params[0..n]` are meaningful per type).
    pub params: [f64; 10],
    /// Sampled points (used only when `seg_type == 0`).
    pub sampled: Vec<f32>,
}

/// A tone curve (lcms2 `cmsToneCurve`).
///
/// `segments` is the floating-point description (empty for a pure tabulated
/// curve); `table16` is the 16-bit limited-precision approximation used by the
/// integer fast paths. Constructors that populate these land in a later task.
#[derive(Clone, Debug, PartialEq)]
pub struct ToneCurve {
    pub(crate) segments: Vec<CurveSegment>,
    pub(crate) table16: Vec<u16>,
}
