//! Complete package inventory. A manifest checks integrity, not publisher trust.
use crate::{Result, digest};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct FileHash {
    path: String,
    sha256: String,
}

pub(crate) fn inventory(dist: &Path) -> Result<Vec<FileHash>> {
    fn visit(root: &Path, dir: &Path, files: &mut Vec<FileHash>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err(format!("Unexpected package symlink: {}", path.display()).into());
            }
            if kind.is_dir() {
                visit(root, &path, files)?;
            } else if kind.is_file() {
                let relative = path.strip_prefix(root)?;
                // Only the root manifest excludes itself from its inventory.
                if relative == Path::new("manifest.json") {
                    continue;
                }
                let path = relative
                    .components()
                    .map(|part| {
                        part.as_os_str()
                            .to_str()
                            .ok_or("Package paths must be valid UTF-8")
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .join("/");
                files.push(FileHash {
                    path,
                    sha256: digest(&entry.path())?,
                });
            } else {
                return Err(format!("Unexpected package file type: {}", path.display()).into());
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(dist, dist, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

pub(crate) fn verify(dist: &Path) -> Result<usize> {
    let manifest_path = dist.join("manifest.json");
    if !fs::symlink_metadata(&manifest_path)?.file_type().is_file() {
        return Err("Package manifest must be a regular file, not a symlink".into());
    }
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest_path)?)?;
    if manifest["schema_version"] != 2 {
        return Err(
            "Complete inventory requires manifest schema version 2; rebuild this package".into(),
        );
    }
    let expected: Vec<FileHash> = serde_json::from_value(manifest["files"].clone())?;
    if expected.is_empty() {
        return Err("Package manifest has no files".into());
    }
    let actual = inventory(dist)?;
    if actual != expected {
        return Err(
            "Package inventory mismatch: missing, modified, extra or unsorted files".into(),
        );
    }
    Ok(actual.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "studio-package-manifest-{}-{stamp}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, bytes: &[u8]) {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        fn seal(&self) {
            let files = inventory(&self.0).unwrap();
            self.write(
                "manifest.json",
                &serde_json::to_vec(&serde_json::json!({
                    "schema_version":2, "files":files,
                }))
                .unwrap(),
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn inventory_covers_metadata_and_signatures_after_packaging() {
        let f = Fixture::new();
        f.write("Masscan Studio.app/Contents/MacOS/studio-ui", b"binary");
        f.write("Masscan Studio.app/Contents/Info.plist", b"plist");
        f.write(
            "Masscan Studio.app/Contents/_CodeSignature/CodeResources",
            b"signature",
        );
        f.write(
            "resources/manifest.json",
            b"nested manifest must be included",
        );
        f.seal();
        assert_eq!(verify(&f.0).unwrap(), 4);
        f.write("Masscan Studio.app/Contents/Info.plist", b"modified plist");
        assert!(verify(&f.0).unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn verifier_rejects_missing_and_extra_files() {
        let f = Fixture::new();
        f.write("studio-ui", b"binary");
        f.seal();
        f.write("extra.dll", b"extra");
        assert!(verify(&f.0).is_err());
        fs::remove_file(f.0.join("extra.dll")).unwrap();
        assert_eq!(verify(&f.0).unwrap(), 1);
        fs::remove_file(f.0.join("studio-ui")).unwrap();
        assert!(verify(&f.0).is_err());
    }

    #[test]
    fn verifier_rejects_legacy_and_empty_manifests() {
        let f = Fixture::new();
        f.write("manifest.json", br#"{"files":[]}"#);
        assert!(
            verify(&f.0)
                .unwrap_err()
                .to_string()
                .contains("schema version 2")
        );
        f.seal();
        assert!(verify(&f.0).unwrap_err().to_string().contains("no files"));
    }

    #[test]
    fn verifier_rejects_manifest_path_traversal_and_duplicates() {
        let f = Fixture::new();
        f.write("studio-ui", b"binary");
        f.seal();
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(f.0.join("manifest.json")).unwrap()).unwrap();
        for path in [
            "../studio-ui",
            "/studio-ui",
            "./studio-ui",
            "sub/../studio-ui",
            "C:/studio-ui",
        ] {
            let mut changed = original.clone();
            changed["files"][0]["path"] = path.into();
            f.write("manifest.json", &serde_json::to_vec(&changed).unwrap());
            assert!(verify(&f.0).is_err(), "accepted {path}");
        }
        let mut changed = original;
        let duplicate = changed["files"][0].clone();
        changed["files"].as_array_mut().unwrap().push(duplicate);
        f.write("manifest.json", &serde_json::to_vec(&changed).unwrap());
        assert!(verify(&f.0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn inventory_does_not_follow_symlinks() {
        let f = Fixture::new();
        std::os::unix::fs::symlink("/", f.0.join("outside")).unwrap();
        assert!(inventory(&f.0).unwrap_err().to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn verifier_rejects_manifest_symlink_before_reading_target() {
        let f = Fixture::new();
        std::os::unix::fs::symlink("missing-outside-file", f.0.join("manifest.json")).unwrap();
        assert!(
            verify(&f.0)
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
    }
}
