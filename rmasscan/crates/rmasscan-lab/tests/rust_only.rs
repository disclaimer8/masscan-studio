//! Language policy: active lab entry points must not grow an interpreter dependency again.
use std::{fs, path::Path};
fn visit(path: &Path, violations: &mut Vec<String>) {
    for e in fs::read_dir(path).unwrap() {
        let p = e.unwrap().path();
        if p.file_name().is_some_and(|n| n == "__pycache__") {
            continue;
        }
        if p.is_dir() {
            visit(&p, violations);
        } else if p.extension().is_some_and(|x| x == "py") {
            violations.push(p.display().to_string());
        } else if p
            .extension()
            .is_some_and(|x| x == "sh" || x == "ps1" || x == "cmd")
        {
            for (line, text) in fs::read_to_string(&p).unwrap().lines().enumerate() {
                let text = text.trim().to_ascii_lowercase();
                if !text.starts_with('#') && !text.starts_with("rem ") && text.contains("python") {
                    violations.push(format!(
                        "{}:{} invokes an interpreter",
                        p.display(),
                        line + 1
                    ));
                }
            }
        }
    }
}
#[test]
fn active_lab_has_no_python_programs() {
    let mut found = Vec::new();
    visit(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts"),
        &mut found,
    );
    assert!(found.is_empty(), "active interpreted programs: {found:?}");
}
