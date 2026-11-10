//! Complete home paths in uncompressed UTF-8/UTF-16 bytes, not bare redaction prefixes.
use crate::Result;
use serde::Serialize;
use std::{fs, path::Path};

#[derive(Clone, Copy)]
enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    fn bytes(self, text: &str) -> Vec<u8> {
        match self {
            Self::Utf8 => text.as_bytes().to_vec(),
            Self::Utf16Le => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            Self::Utf16Be => text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        }
    }

    fn decode(self, bytes: &[u8]) -> Option<String> {
        match self {
            Self::Utf8 => std::str::from_utf8(bytes).ok().map(str::to_owned),
            Self::Utf16Le | Self::Utf16Be => {
                let words = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| match self {
                        Self::Utf16Le => u16::from_le_bytes([pair[0], pair[1]]),
                        _ => u16::from_be_bytes([pair[0], pair[1]]),
                    })
                    .collect::<Vec<_>>();
                String::from_utf16(&words).ok()
            }
        }
    }

    fn width(self) -> usize {
        match self {
            Self::Utf8 => 1,
            _ => 2,
        }
    }
}

#[derive(Default, Debug, Serialize, PartialEq, Eq)]
struct Counts {
    utf8: usize,
    utf16_le: usize,
    utf16_be: usize,
}

impl Counts {
    fn total(&self) -> usize {
        self.utf8 + self.utf16_le + self.utf16_be
    }
}

#[derive(Serialize)]
struct Finding {
    file: String,
    matches: Counts,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    scope: &'static str,
    inventory_files_verified: usize,
    files_scanned: usize,
    findings: Vec<Finding>,
    ok: bool,
}

pub(crate) fn main_entry() -> Result<()> {
    let args = std::env::args_os().skip(2).collect::<Vec<_>>();
    let [directory] = args.as_slice() else {
        return Err("Usage: cargo xtask verify-package-privacy PACKAGE_DIR".into());
    };
    if directory.is_empty() {
        return Err("Package directory is required".into());
    }
    let report = verify(Path::new(directory))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.ok {
        return Err("Package contains complete user-home paths; values withheld".into());
    }
    Ok(())
}

fn verify(directory: &Path) -> Result<Report> {
    let inventory_files_verified = crate::package_manifest::verify(directory)
        .map_err(|_| "Package inventory verification failed")?;
    let mut report = Report {
        schema_version: 1,
        scope: "complete home paths in uncompressed UTF-8/UTF-16LE/UTF-16BE; doubled Windows separators included; encoding counts may overlap; not arbitrary private tokens, archives or Unicode escape decoding",
        inventory_files_verified,
        files_scanned: 0,
        findings: Vec::new(),
        ok: true,
    };
    visit(directory, directory, &mut report)?;
    report
        .findings
        .sort_by(|left, right| left.file.cmp(&right.file));
    report.ok = report.findings.is_empty();
    Ok(report)
}

fn visit(root: &Path, directory: &Path, report: &mut Report) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(|_| "Cannot enumerate package files")? {
        let entry = entry.map_err(|_| "Cannot enumerate package entry")?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|_| "Cannot inspect package entry")?;
        if kind.is_dir() {
            visit(root, &path, report)?;
        } else if kind.is_file() {
            let bytes = fs::read(&path).map_err(|_| "Cannot read package file")?;
            let matches = count_paths(&bytes);
            report.files_scanned += 1;
            if matches.total() != 0 {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "Invalid package path")?;
                let file = relative
                    .components()
                    .map(|part| part.as_os_str().to_str().ok_or("Package path is not UTF-8"))
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .join("/");
                report.findings.push(Finding { file, matches });
            }
        } else {
            return Err("Package entry is not a regular file or directory".into());
        }
    }
    Ok(())
}

fn count_paths(bytes: &[u8]) -> Counts {
    Counts {
        utf8: count_encoding(bytes, Encoding::Utf8),
        utf16_le: count_encoding(bytes, Encoding::Utf16Le),
        utf16_be: count_encoding(bytes, Encoding::Utf16Be),
    }
}

fn count_encoding(bytes: &[u8], encoding: Encoding) -> usize {
    let mut count = 0;
    for (prefix, separator, insensitive) in [
        ("/Users/", "/", false),
        ("/home/", "/", false),
        ("\\Users\\", "\\", true),
        ("\\\\Users\\\\", "\\\\", true),
    ] {
        let prefix = encoding.bytes(prefix);
        let separator = encoding.bytes(separator);
        for (offset, window) in bytes.windows(prefix.len()).enumerate() {
            let matched = if insensitive {
                window.eq_ignore_ascii_case(&prefix)
            } else {
                window == prefix
            };
            if matched && has_account(&bytes[offset + prefix.len()..], &separator, encoding) {
                count += 1;
            }
        }
    }
    count
}

const MAX_ACCOUNT_BYTES: usize = 1024;

fn has_account(bytes: &[u8], separator: &[u8], encoding: Encoding) -> bool {
    // Bound the component independently of the surrounding binary's length.
    // A separator means a descendant path. End, NUL and a closing double quote
    // also establish the account's home root. Spaces/apostrophes remain name characters.
    for end in (0..=bytes.len().min(MAX_ACCOUNT_BYTES)).step_by(encoding.width()) {
        if end == bytes.len() || bytes[end..].starts_with(separator) {
            return valid_account(&bytes[..end], encoding);
        }
        let unit = &bytes[end..bytes.len().min(end + encoding.width())];
        if unit.len() != encoding.width() {
            return false;
        }
        // Check ASCII delimiters directly without rejecting multibyte UTF-8 or surrogates.
        let ascii = match encoding {
            Encoding::Utf8 => (unit[0] < 128).then_some(unit[0]),
            Encoding::Utf16Le => (unit[1] == 0 && unit[0] < 128).then_some(unit[0]),
            Encoding::Utf16Be => (unit[0] == 0 && unit[1] < 128).then_some(unit[1]),
        };
        if matches!(ascii, Some(0 | b'"')) {
            return valid_account(&bytes[..end], encoding);
        }
        if ascii.is_some_and(|byte| !valid_account_character(char::from(byte))) {
            return false;
        }
    }
    false
}

fn valid_account(bytes: &[u8], encoding: Encoding) -> bool {
    encoding.decode(bytes).is_some_and(|account| {
        !account.trim().is_empty()
            && !matches!(account.as_str(), "." | "..")
            && account.chars().all(valid_account_character)
    })
}

fn valid_account_character(character: char) -> bool {
    !character.is_control()
        && !matches!(
            character,
            '/' | '\\' | ':' | '"' | '<' | '>' | '|' | '?' | '*'
        )
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
        fn new(content: &[u8]) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "studio-path-audit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            fs::create_dir(directory.join("nested")).unwrap();
            fs::write(directory.join("nested/app"), content).unwrap();
            let inventory = crate::package_manifest::inventory(&directory).unwrap();
            fs::write(
                directory.join("manifest.json"),
                serde_json::to_vec(&serde_json::json!({
                    "schema_version": 2, "files": inventory,
                }))
                .unwrap(),
            )
            .unwrap();
            Self(directory)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn verifies_inventory_and_scans_manifest_as_well_as_nested_files() {
        let fixture = Fixture::new(b"/Users//home/");
        let report = verify(&fixture.0).unwrap();
        assert!(report.ok);
        assert_eq!(report.inventory_files_verified, 1);
        assert_eq!(report.files_scanned, 2);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn reports_relative_filename_without_account_or_absolute_directory() {
        let fixture = Fixture::new(b"/home/private-fixture-account/source");
        let report = verify(&fixture.0).unwrap();
        assert!(!report.ok);
        assert_eq!(report.findings[0].file, "nested/app");
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("private-fixture-account"));
        assert!(!json.contains(&fixture.0.to_string_lossy().to_string()));
    }

    #[test]
    fn rejects_inventory_mismatch_before_path_audit_with_sanitized_error() {
        let fixture = Fixture::new(b"clean");
        fs::write(fixture.0.join("nested/app"), b"changed").unwrap();
        let error = verify(&fixture.0).err().unwrap().to_string();
        assert_eq!(error, "Package inventory verification failed");
    }

    #[test]
    fn detects_complete_paths_across_supported_platforms() {
        for path in [
            "/Users/alice/source",
            "/home/build-user/.cargo/registry",
            r"C:\Users\Alice Example\source",
            r"C:\users\ALICE\source",
            r"C:\\Users\\Alice Example\\source",
            "/Users/Zoë 文/Library",
            r"C:\Users\O'Neil\source",
        ] {
            assert_eq!(count_paths(path.as_bytes()).utf8, 1, "fixture {path:?}");
        }
    }

    #[test]
    fn ignores_bare_and_adjacent_redaction_prefixes() {
        for text in [
            "/Users/",
            "/home/",
            "/Users//home/",
            "/home//Users/",
            r"\Users\",
            r"\\Users\\",
            "/Users/ /file",
            "/home/../file",
            "/Users/\0unrelated/file",
            "/Users/\ntext/file",
            "/Users/\"literal\"/file",
            r"\Users\unexpected/path",
        ] {
            assert_eq!(count_paths(text.as_bytes()).total(), 0, "fixture {text:?}");
        }
    }

    #[test]
    fn detects_home_roots_at_end_nul_and_double_quote_boundaries() {
        for encoding in [Encoding::Utf8, Encoding::Utf16Le, Encoding::Utf16Be] {
            for root in [
                "/Users/alice",
                "/home/build-user",
                r"C:\Users\Alice Example",
                r"C:\\Users\\Alice Example",
                "/Users/Zoë 文 😀",
            ] {
                for suffix in ["", "\0unrelated", "\" trailing text"] {
                    let mut bytes = vec![0xfe];
                    bytes.extend(encoding.bytes(&format!("{root}{suffix}")));
                    let counts = count_paths(&bytes);
                    assert_eq!(
                        match encoding {
                            Encoding::Utf8 => counts.utf8,
                            Encoding::Utf16Le => counts.utf16_le,
                            Encoding::Utf16Be => counts.utf16_be,
                        },
                        1,
                        "fixture {root:?}{suffix:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn bare_prefixes_remain_clean_at_root_terminators() {
        for encoding in [Encoding::Utf8, Encoding::Utf16Le, Encoding::Utf16Be] {
            for prefix in [
                "/Users/",
                "/home/",
                r"\Users\",
                r"\\Users\\",
                "/Users//home/",
            ] {
                for suffix in ["", "\0unrelated", "\" trailing text"] {
                    assert_eq!(
                        count_paths(&encoding.bytes(&format!("{prefix}{suffix}"))).total(),
                        0
                    );
                }
            }
        }
    }

    #[test]
    fn limits_account_component_before_accepting_a_terminator() {
        for encoding in [Encoding::Utf8, Encoding::Utf16Le, Encoding::Utf16Be] {
            let at_limit = "a".repeat(MAX_ACCOUNT_BYTES / encoding.width());
            let too_long = format!("{at_limit}a");
            for suffix in ["", "\0later", "\" quoted", "/source"] {
                let counts = count_paths(&encoding.bytes(&format!("/Users/{at_limit}{suffix}")));
                assert_eq!(
                    match encoding {
                        Encoding::Utf8 => counts.utf8,
                        Encoding::Utf16Le => counts.utf16_le,
                        Encoding::Utf16Be => counts.utf16_be,
                    },
                    1
                );
                assert_eq!(
                    count_paths(&encoding.bytes(&format!("/Users/{too_long}{suffix}"))).total(),
                    0
                );
            }
        }
    }

    #[test]
    fn accepts_unicode_and_spaces_in_both_utf16_orders_at_any_alignment() {
        for encoding in [Encoding::Utf16Le, Encoding::Utf16Be] {
            for padding in [0, 1, 2] {
                let mut bytes = vec![0xfe; padding];
                bytes.extend(encoding.bytes(r"C:\Users\Zoë 文 😀\source"));
                let counts = count_paths(&bytes);
                assert_eq!(counts.utf8, 0);
                assert_eq!(counts.total(), 1);
                match encoding {
                    Encoding::Utf16Le => assert_eq!(counts.utf16_le, 1),
                    Encoding::Utf16Be => assert_eq!(counts.utf16_be, 1),
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn does_not_join_strings_across_controls_or_invalid_encoding() {
        let mut utf8 = b"/Users/".to_vec();
        utf8.extend([0xff, b'/']);
        assert_eq!(count_paths(&utf8).total(), 0);
        for encoding in [Encoding::Utf16Le, Encoding::Utf16Be] {
            assert_eq!(
                count_paths(&encoding.bytes("/Users/\0later/path")).total(),
                0
            );
            let mut bytes = encoding.bytes("/Users/");
            bytes.extend(match encoding {
                Encoding::Utf16Le => 0xd800_u16.to_le_bytes(),
                _ => 0xd800_u16.to_be_bytes(),
            });
            bytes.extend(encoding.bytes("/file"));
            assert_eq!(count_paths(&bytes).total(), 0);
        }
    }

    #[test]
    fn counts_multiple_paths_without_disclosing_values() {
        let bytes = b"/home/alice/src\0/Users/bob/src";
        let counts = count_paths(bytes);
        assert_eq!(counts.utf8, 2);
        let json = serde_json::to_string(&counts).unwrap();
        assert!(!json.contains("alice"));
        assert!(!json.contains("bob"));
    }
}
