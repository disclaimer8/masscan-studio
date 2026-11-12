//! Direct ELF GLIBC requirements only; runtime acceptance remains separate.
use crate::Result;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version(Vec<u32>);

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, part) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(".")?;
            }
            write!(formatter, "{part}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Options {
    dist: PathBuf,
    maximum: Version,
}

#[derive(Debug, Serialize)]
struct BinaryReport {
    executable: &'static str,
    required_glibc: Vec<String>,
    highest_required_glibc: String,
    ok: bool,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    scope: &'static str,
    inventory_files_verified: usize,
    max_glibc: String,
    binaries: Vec<BinaryReport>,
    ok: bool,
}

fn options(args: Vec<OsString>) -> Result<Options> {
    let usage = "Usage: cargo xtask verify-linux-abi PACKAGE_DIR --max-glibc MAJOR.MINOR[.PATCH]";
    let [dist, flag, maximum] = args.as_slice() else {
        return Err(usage.into());
    };
    if dist.is_empty() || flag != "--max-glibc" {
        return Err(usage.into());
    }
    Ok(Options {
        dist: PathBuf::from(dist),
        maximum: parse_version(maximum.to_str().ok_or(usage)?)?,
    })
}

pub(crate) fn main_entry() -> Result<()> {
    let options = options(std::env::args_os().skip(2).collect())?;
    let report = verify_with(&options.dist, &options.maximum, read_versions)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.ok {
        return Err("Packaged executable GLIBC requirements exceed --max-glibc".into());
    }
    Ok(())
}

fn verify_with(
    dist: &Path,
    maximum: &Version,
    mut inspect: impl FnMut(&Path) -> Result<Vec<Version>>,
) -> Result<Report> {
    // The shared inventory verifier can include filesystem paths in diagnostics.
    // This command's evidence deliberately reports no package or source paths.
    let count = crate::package_manifest::verify(dist)
        .map_err(|_| "Package inventory verification failed (manifest missing, malformed or inventory mismatch)")?;
    let mut binaries = Vec::new();
    for executable in ["studio-ui", "studio-runner", "studio-inspect"] {
        let path = dist.join(executable);
        validate_elf(&path).map_err(|error| format!("{executable}: {error}"))?;
        let versions = inspect(&path).map_err(|error| format!("{executable}: {error}"))?;
        let highest = versions
            .iter()
            .max()
            .ok_or_else(|| format!("{executable}: no GLIBC requirements found"))?;
        binaries.push(BinaryReport {
            executable,
            required_glibc: versions
                .iter()
                .map(|version| format!("GLIBC_{version}"))
                .collect(),
            highest_required_glibc: format!("GLIBC_{highest}"),
            ok: highest <= maximum,
        });
    }
    Ok(Report {
        schema_version: 1,
        scope: "direct_executable_glibc_requirements_only; not full distribution compatibility",
        inventory_files_verified: count,
        max_glibc: maximum.to_string(),
        ok: binaries.iter().all(|binary| binary.ok),
        binaries,
    })
}

fn validate_elf(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)
        .map_err(|_| "required executable is missing or inaccessible")?
        .file_type()
        .is_file()
    {
        return Err("required executable must be a regular file".into());
    }
    let mut header = [0_u8; 18];
    fs::File::open(path)
        .map_err(|_| "cannot open required executable")?
        .read_exact(&mut header)
        .map_err(|_| "truncated ELF header")?;
    if &header[..4] != b"\x7fELF" || !matches!(header[4], 1 | 2) || header[6] != 1 {
        return Err("invalid ELF header".into());
    }
    let kind = match header[5] {
        1 => u16::from_le_bytes([header[16], header[17]]),
        2 => u16::from_be_bytes([header[16], header[17]]),
        _ => return Err("invalid ELF byte order".into()),
    };
    if !matches!(kind, 2 | 3) {
        return Err("ELF must be an executable or position-independent executable".into());
    }
    Ok(())
}

fn read_versions(path: &Path) -> Result<Vec<Version>> {
    let output = Command::new("readelf")
        .env("LC_ALL", "C")
        .args(["--wide", "--version-info", "--"])
        .arg(path)
        .output()
        .map_err(|_| "cannot run readelf; install GNU binutils")?;
    // readelf can emit warnings for malformed ELF while exiting successfully.
    // Never echo its stderr: it can contain absolute paths from the input file.
    if !output.status.success() || !output.stderr.iter().all(u8::is_ascii_whitespace) {
        return Err("readelf failed or reported malformed ELF diagnostics".into());
    }
    let output =
        std::str::from_utf8(&output.stdout).map_err(|_| "readelf returned non-UTF-8 output")?;
    requirements(output)
}

fn parse_version(value: &str) -> Result<Version> {
    let mut parts = Vec::new();
    for part in value.split('.') {
        if part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return Err("Expected a numeric GLIBC major.minor[.patch] version".into());
        }
        parts.push(
            part.parse::<u32>()
                .map_err(|_| "GLIBC version component overflows")?,
        );
    }
    if !(2..=3).contains(&parts.len()) {
        return Err("Expected a numeric GLIBC major.minor[.patch] version".into());
    }
    if parts.len() == 3 && parts[2] == 0 {
        parts.pop();
    }
    Ok(Version(parts))
}

fn requirements(output: &str) -> Result<Vec<Version>> {
    let malformed = "Malformed or unsupported readelf version-needs output";
    let mut in_needs = false;
    let mut expected_files = None;
    let mut files = 0;
    let mut remaining_names = 0;
    let mut versions = BTreeSet::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with("Version needs section ") {
            if expected_files.is_some() {
                return Err(malformed.into());
            }
            let (_, count) = line.rsplit_once(" contains ").ok_or(malformed)?;
            let count = count
                .strip_suffix(" entries:")
                .or_else(|| count.strip_suffix(" entry:"))
                .ok_or(malformed)?;
            let count = count.parse::<usize>().map_err(|_| malformed)?;
            if count == 0 {
                return Err(malformed.into());
            }
            expected_files = Some(count);
            in_needs = true;
            continue;
        }
        if line.starts_with("Version ") {
            in_needs = false;
        }
        if !in_needs {
            continue;
        }
        if line.starts_with("Addr:") {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let offset = fields
            .first()
            .and_then(|value| value.strip_suffix(':'))
            .ok_or(malformed)?;
        let offset = offset.strip_prefix("0x").unwrap_or(offset);
        if offset.is_empty() || !offset.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(malformed.into());
        }
        match fields.as_slice() {
            [_, "Version:", "1", "File:", _, "Cnt:", count] => {
                if remaining_names != 0 {
                    return Err(malformed.into());
                }
                remaining_names = count.parse::<usize>().map_err(|_| malformed)?;
                if remaining_names == 0 {
                    return Err(malformed.into());
                }
                files += 1;
            }
            [
                _,
                "Name:",
                name,
                "Flags:",
                "none" | "WEAK",
                "Version:",
                index,
            ] => {
                if remaining_names == 0 || index.parse::<u16>().is_err() {
                    return Err(malformed.into());
                }
                remaining_names -= 1;
                if name.starts_with("GLIBC") && !name.starts_with("GLIBCXX_") {
                    let value = name.strip_prefix("GLIBC_").ok_or(malformed)?;
                    versions.insert(parse_version(value).map_err(|_| {
                        "Unsupported GLIBC requirement: only numeric GLIBC_major.minor[.patch] tags are supported (GLIBC_ABI_* and GLIBC_PRIVATE fail closed)"
                    })?);
                }
            }
            _ => return Err(malformed.into()),
        }
    }
    if expected_files != Some(files) || remaining_names != 0 || versions.is_empty() {
        return Err("Missing, truncated or unsupported GLIBC requirements".into());
    }
    Ok(versions.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    const NEEDS: &str = "\
Version symbols section '.gnu.version' contains 4 entries:
 Addr: 0x0000000000000600  Offset: 0x00000600  Link: 6 (.dynsym)
  000:   0 (*local*)       2 (GLIBC_9.99)       3 (GLIBC_2.34)
Version needs section '.gnu.version_r' contains 2 entries:
 Addr: 0x0000000000000610  Offset: 0x00000610  Link: 7 (.dynstr)
  000000: Version: 1  File: libgcc_s.so.1  Cnt: 1
  0x0010:   Name: GCC_3.0  Flags: none  Version: 5
  0x0020: Version: 1  File: libc.so.6  Cnt: 4
  0x0030:   Name: GLIBC_2.34  Flags: none  Version: 4
  0x0040:   Name: GLIBC_2.2.5  Flags: none  Version: 3
  0x0050:   Name: GLIBC_2.9  Flags: none  Version: 2
  0x0060:   Name: GLIBC_2.34  Flags: WEAK  Version: 6
";

    #[test]
    fn compares_versions_numerically_including_patch_components() {
        assert!(parse_version("2.9").unwrap() < parse_version("2.34").unwrap());
        assert!(parse_version("2.39.1").unwrap() > parse_version("2.39").unwrap());
        assert_eq!(
            parse_version("2.39.0").unwrap(),
            parse_version("2.39").unwrap()
        );
        assert!(parse_version("3.0").unwrap() > parse_version("2.99").unwrap());
    }

    #[test]
    fn rejects_invalid_or_unsupported_version_syntax() {
        for value in [
            "",
            "2",
            "2.",
            ".39",
            "2..39",
            "2.39.1.2",
            "02.39",
            "2.039",
            "2.+39",
            " 2.39",
            "2.39\n",
            "2.4294967296",
            "ABI_DT_RELR",
            "PRIVATE",
        ] {
            assert!(parse_version(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn reads_only_requirements_and_sorts_deduplicated_versions_numerically() {
        assert_eq!(
            requirements(NEEDS).unwrap(),
            vec![
                Version(vec![2, 2, 5]),
                Version(vec![2, 9]),
                Version(vec![2, 34])
            ]
        );
    }

    #[test]
    fn accepts_a_single_needed_library_and_keeps_glibcxx_separate() {
        let single = "Version needs section '.gnu.version_r' contains 1 entry:\n 000000: Version: 1  File: libc.so.6  Cnt: 1\n 0x0010: Name: GLIBC_2.39  Flags: none  Version: 2\n";
        assert_eq!(requirements(single).unwrap(), vec![Version(vec![2, 39])]);
        assert_eq!(
            requirements(&NEEDS.replace("GCC_3.0", "GLIBCXX_3.4.30")).unwrap(),
            requirements(NEEDS).unwrap()
        );
    }

    #[test]
    fn rejects_nonnumeric_glibc_constraints_including_weak_ones() {
        for tag in [
            "GLIBC_ABI_DT_RELR",
            "GLIBC_PRIVATE",
            "GLIBC_2.39junk",
            "GLIBC_",
            "GLIBC",
        ] {
            let changed = NEEDS.replace("GLIBC_2.34  Flags: WEAK", &format!("{tag}  Flags: WEAK"));
            assert!(requirements(&changed).is_err(), "accepted {tag}");
        }
    }

    #[test]
    fn rejects_missing_truncated_or_malformed_requirements() {
        for output in [
            "".to_owned(),
            "No version information found in this file.".to_owned(),
            NEEDS.replace("GLIBC_", "OTHER_"),
            NEEDS.replace("contains 2 entries", "contains 3 entries"),
            NEEDS.replace("Cnt: 4", "Cnt: 5"),
            NEEDS.replace("Cnt: 4", "Cnt: 3"),
            NEEDS.replace("Name: GLIBC_2.34", "Missing: GLIBC_2.34"),
            NEEDS.replace("Version: 1  File", "Version: 2  File"),
            NEEDS.replace("Version: 6", "Version: corrupt"),
            NEEDS.replace("0x0060:", "corrupt:"),
            NEEDS.replace("Flags: WEAK", "Flags: UNKNOWN"),
            format!("{NEEDS}\n{NEEDS}"),
        ] {
            assert!(
                requirements(&output).is_err(),
                "accepted malformed readelf output"
            );
        }
    }

    struct Package(PathBuf);
    impl Package {
        fn new() -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let root = if cfg!(unix) {
                PathBuf::from("/tmp")
            } else {
                std::env::temp_dir()
            };
            let path = root.join(format!(
                "studio-linux-abi-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let package = Self(path);
            let mut elf = [0_u8; 64];
            elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            elf[16] = 3; // ELF64 little-endian ET_DYN; readelf checks the remainder.
            for name in ["studio-ui", "studio-runner", "studio-inspect"] {
                fs::write(package.0.join(name), elf).unwrap();
            }
            package.seal();
            package
        }

        fn seal(&self) {
            fs::write(self.0.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
                "schema_version": 2, "files": crate::package_manifest::inventory(&self.0).unwrap(),
            })).unwrap()).unwrap();
        }
    }
    impl Drop for Package {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn accepts_exact_ceiling_and_reports_all_three_executables_without_paths() {
        let package = Package::new();
        let report = verify_with(&package.0, &parse_version("2.39").unwrap(), |_| {
            Ok(vec![Version(vec![2, 39])])
        })
        .unwrap();
        assert!(report.ok);
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["inventory_files_verified"], 3);
        assert_eq!(json["max_glibc"], "2.39");
        assert_eq!(json["binaries"][0]["executable"], "studio-ui");
        assert_eq!(json["binaries"][1]["executable"], "studio-runner");
        assert_eq!(json["binaries"][2]["executable"], "studio-inspect");
        assert_eq!(
            json["binaries"][0]["required_glibc"],
            serde_json::json!(["GLIBC_2.39"])
        );
        assert!(
            !json
                .to_string()
                .contains(&package.0.to_string_lossy().to_string())
        );
    }

    #[test]
    fn rejects_over_ceiling_in_any_executable_and_retains_evidence() {
        let package = Package::new();
        for offender in ["studio-ui", "studio-runner", "studio-inspect"] {
            let report = verify_with(&package.0, &parse_version("2.39").unwrap(), |path| {
                Ok(vec![if path.file_name().unwrap() == offender {
                    Version(vec![2, 43])
                } else {
                    Version(vec![2, 9])
                }])
            })
            .unwrap();
            assert!(!report.ok, "accepted {offender}");
            let binary = report
                .binaries
                .iter()
                .find(|binary| binary.executable == offender)
                .unwrap();
            assert!(!binary.ok);
            assert_eq!(binary.highest_required_glibc, "GLIBC_2.43");
        }
    }

    #[test]
    fn rejects_inventory_mismatch_before_inspecting_any_binary() {
        let package = Package::new();
        fs::write(package.0.join("studio-runner"), b"modified").unwrap();
        let mut inspected = false;
        let error = verify_with(&package.0, &parse_version("2.39").unwrap(), |_| {
            inspected = true;
            requirements(NEEDS)
        })
        .unwrap_err()
        .to_string();
        assert!(!inspected);
        assert!(error.contains("inventory"));
        assert!(!error.contains(&package.0.to_string_lossy().to_string()));
    }

    #[test]
    fn rejects_missing_required_executable_even_if_inventory_is_valid() {
        let package = Package::new();
        fs::remove_file(package.0.join("studio-inspect")).unwrap();
        package.seal();
        assert!(
            verify_with(&package.0, &parse_version("2.39").unwrap(), |_| {
                requirements(NEEDS)
            })
            .unwrap_err()
            .to_string()
            .contains("studio-inspect")
        );
    }

    #[test]
    fn rejects_non_elf_truncated_and_nonexecutable_elf_before_readelf() {
        let package = Package::new();
        let mut relocatable = [0_u8; 64];
        relocatable[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        relocatable[16] = 1;
        for bytes in [
            b"not ELF".as_slice(),
            b"\x7fELF".as_slice(),
            relocatable.as_slice(),
        ] {
            fs::write(package.0.join("studio-ui"), bytes).unwrap();
            package.seal();
            let mut inspected = false;
            let error = verify_with(&package.0, &parse_version("2.39").unwrap(), |_| {
                inspected = true;
                requirements(NEEDS)
            })
            .unwrap_err()
            .to_string();
            assert!(!inspected);
            assert!(error.contains("studio-ui"));
        }
    }

    #[test]
    fn readelf_failures_or_missing_versions_do_not_become_passes() {
        let package = Package::new();
        assert!(
            verify_with(&package.0, &parse_version("2.39").unwrap(), |_| Err(
                "readelf failed".into()
            ))
            .is_err()
        );
        assert!(verify_with(&package.0, &parse_version("2.39").unwrap(), |_| Ok(vec![])).is_err());
    }

    #[test]
    fn requires_explicit_valid_maximum_and_rejects_extra_cli_arguments() {
        let parsed = options(
            ["package", "--max-glibc", "2.39"]
                .map(OsString::from)
                .to_vec(),
        )
        .unwrap();
        assert_eq!(parsed.dist, PathBuf::from("package"));
        assert_eq!(parsed.maximum, Version(vec![2, 39]));
        for args in [
            vec![],
            vec!["package"],
            vec!["package", "--max-glibc"],
            vec!["package", "--max-glibc", "2.39", "extra"],
            vec!["package", "--wrong", "2.39"],
            vec!["package", "--max-glibc", "ABI_DT_RELR"],
        ] {
            assert!(options(args.into_iter().map(OsString::from).collect()).is_err());
        }
    }
}
