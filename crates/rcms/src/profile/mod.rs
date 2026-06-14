//! ICC profile parsing. The 128-byte header (`header`), the tag directory
//! (`directory`), and the tag-descriptor table (`descriptor`) compose into
//! `Profile`. Tag *values* (decoded per-type) arrive in later slice-2 tasks.

pub mod descriptor;
pub mod directory;
pub mod header;

pub use directory::TagEntry;
pub use header::{ColorSpace, DateTime, Header, ProfileClass, RenderingIntent};

use crate::error::Result;
use crate::io::MemReader;
use crate::sig::Signature;
use core::cell::RefCell;
use std::collections::BTreeMap;

/// A parsed ICC profile: the validated header plus the accepted tag directory.
/// Borrows the source bytes so positioned tag reads (Task 3+) can decode values
/// lazily without copying. `cache` is a placeholder for those decoded values.
pub struct Profile<'a> {
    bytes: &'a [u8],
    header: Header,
    dir: Vec<TagEntry>,
    /// Placeholder for the per-tag decoded-value cache (populated in Task 3).
    #[allow(dead_code)]
    cache: RefCell<BTreeMap<u32, ()>>,
}

impl<'a> Profile<'a> {
    /// Open a profile from its raw bytes: parse the header (lcms2 `_cmsReadHeader`
    /// header half) then the tag directory (its directory loop + dup check). The
    /// reader is positioned at byte 128 after the header parse, exactly where the
    /// directory begins. Errors propagate from either stage (bad magic/version,
    /// truncation, out-of-range tag count, or a duplicate tag signature).
    pub fn open(bytes: &'a [u8]) -> Result<Profile<'a>> {
        let mut r = MemReader::new(bytes);
        let header = Header::parse(&mut r)?;
        let dir = directory::parse_directory(&mut r, header.size, bytes.len())?;
        Ok(Profile {
            bytes,
            header,
            dir,
            cache: RefCell::new(BTreeMap::new()),
        })
    }

    /// The profile's raw bytes (the slice `open` borrowed).
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The validated 128-byte header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The accepted tag signatures, in directory order.
    pub fn tags(&self) -> impl Iterator<Item = Signature> + '_ {
        self.dir.iter().map(|e| e.sig)
    }

    /// Whether the profile carries a tag with the given signature.
    pub fn has_tag(&self, sig: Signature) -> bool {
        self.dir.iter().any(|e| e.sig == sig)
    }

    /// The directory entry for `sig`, if present.
    pub fn tag_entry(&self, sig: Signature) -> Option<&TagEntry> {
        self.dir.iter().find(|e| e.sig == sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn testbed_dir() -> PathBuf {
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/Little-CMS/testbed"
        ))
        .to_path_buf()
    }

    fn testbed_icc() -> Vec<PathBuf> {
        let mut v: Vec<_> = fs::read_dir(testbed_dir())
            .expect("read testbed")
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("icc"))
            .collect();
        v.sort();
        v
    }

    /// Differential: `Profile::open` accept/reject decision must agree with full
    /// lcms2 `cmsOpenProfileFromMem` (header + directory + dup check) on every
    /// testbed file, and accepted files must carry the same accepted tag SET.
    #[test]
    fn open_and_tags_match_oracle_over_testbed() {
        let files = testbed_icc();
        assert!(!files.is_empty(), "no .icc in testbed");

        let mut compared = 0usize;
        let mut both_accept = 0usize;
        for path in &files {
            let bytes = fs::read(path).unwrap();
            let name = path.file_name().unwrap().to_string_lossy();

            let oracle_ok = rcms_oracle::open_succeeds(&bytes);
            let rust = Profile::open(&bytes);

            assert_eq!(
                rust.is_ok(),
                oracle_ok,
                "open accept/reject disagree on {name}: rust={:?} lcms2={oracle_ok}",
                rust.as_ref().err()
            );

            if oracle_ok {
                both_accept += 1;
                let p = rust.unwrap();
                let rust_set: BTreeSet<u32> = p.tags().map(|s| s.to_raw()).collect();
                let oracle_set: BTreeSet<u32> = rcms_oracle::tag_signatures(&bytes)
                    .expect("oracle tag sigs")
                    .into_iter()
                    .collect();
                assert_eq!(
                    rust_set, oracle_set,
                    "accepted tag set mismatch on {name}\n rust={rust_set:x?}\n lcms2={oracle_set:x?}"
                );
            }
            compared += 1;
        }
        println!(
            "testbed open diff: compared {compared} .icc files, {both_accept} accepted by both"
        );
        assert!(both_accept > 0, "expected at least one accepted profile");
    }

    /// The named malformed files: assert open agreement explicitly (toosmall.icc
    /// is rejected at directory validation by lcms2, and now by rcms too).
    #[test]
    fn malformed_files_agree_with_oracle() {
        for name in ["bad.icc", "bad_mpe.icc", "toosmall.icc"] {
            let path = testbed_dir().join(name);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).unwrap();
            let oracle_ok = rcms_oracle::open_succeeds(&bytes);
            let rust_ok = Profile::open(&bytes).is_ok();
            assert_eq!(rust_ok, oracle_ok, "open disagree on {name}");
        }
    }
}
