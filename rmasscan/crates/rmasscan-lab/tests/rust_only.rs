//! Language policy for the whole repository: no interpreted programs of the banned kind, in
//! any tracked script or source file, and no shebang that names the interpreter.
//!
//! The same policy runs in CI as `scripts/language-guard.sh` (shell, workflow `language-guard.yml`, no
//! path filter). Keep the two in step. The banned word is assembled at run time so this file
//! does not contain it and does not flag itself; there is no path exemption and no comment
//! exemption.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const WORD: &str = concat!("py", "thon");
const SCANNED_EXTENSIONS: &[&str] = &[
    "sh", "bash", "ps1", "cmd", "bat", "swift", "rs", "yml", "yaml",
];
const BANNED_EXTENSIONS: &[&str] = &["py", "pyw", "pyc"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root")
}

/// Tracked files (`git ls-files`); without git, a walk that skips build output.
fn tracked_files(root: &Path) -> Vec<String> {
    if let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        && out.status.success()
        && !out.stdout.is_empty()
    {
        return out
            .stdout
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files
}

fn walk(root: &Path, dir: &Path, files: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if matches!(name.as_str(), ".git" | "target" | ".build" | "node_modules") {
            continue;
        }
        if path.is_dir() {
            walk(root, &path, files);
        } else {
            files.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
}

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The word as a whole token: not glued to letters, digits or `_` on the left; version digits,
/// dots and a windowed-launcher `w` may follow; nothing word-like after that.
fn mentions(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find(WORD) {
        let start = from + at;
        let end = start + WORD.len();
        let before_ok = lower[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !word_char(c));
        let mut rest = &lower[end..];
        rest = rest.trim_start_matches(|c: char| c.is_ascii_digit() || c == '.');
        let rest = rest.strip_prefix('w').unwrap_or(rest);
        // Backtrack-free equivalent of `word[0-9.]*w?(non-word|end)`.
        let after_ok = rest.chars().next().is_none_or(|c| !word_char(c));
        let bare_ok = lower[end..].chars().next().is_none_or(|c| !word_char(c));
        if before_ok && (after_ok || bare_ok) {
            return true;
        }
        from = end;
    }
    false
}

fn shebang_names_interpreter(first_line: &str) -> bool {
    first_line.starts_with("#!") && first_line.to_ascii_lowercase().contains(WORD)
}

/// All policy violations of one tracked file, given its path relative to the root and content.
fn violations_of(rel: &str, bytes: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let ext = Path::new(rel)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if BANNED_EXTENSIONS.contains(&ext) {
        found.push(format!("{rel}: banned source file"));
    }
    let text = String::from_utf8_lossy(bytes);
    let has_shebang = text.starts_with("#!");
    if shebang_names_interpreter(text.lines().next().unwrap_or("")) {
        found.push(format!("{rel}:1: shebang names the banned interpreter"));
    }
    if has_shebang || SCANNED_EXTENSIONS.contains(&ext) {
        for (n, line) in text.lines().enumerate() {
            if mentions(line) {
                found.push(format!("{rel}:{}: mentions the banned interpreter", n + 1));
            }
        }
    }
    found
}

#[test]
fn the_tracked_tree_has_no_interpreted_programs() {
    let root = repo_root();
    let files = tracked_files(&root);
    assert!(
        files
            .iter()
            .any(|f| f == "rmasscan/crates/rmasscan-lab/tests/rust_only.rs"),
        "file enumeration is broken: {} files, this test not among them",
        files.len()
    );
    let mut found = Vec::new();
    for rel in &files {
        let path = root.join(rel);
        if path.is_symlink() || !path.is_file() {
            continue;
        }
        found.extend(violations_of(rel, &fs::read(&path).unwrap()));
    }
    assert!(
        found.is_empty(),
        "interpreter policy violations: {found:#?}"
    );
}

#[test]
fn the_matcher_flags_every_form_of_invocation_a_comment_included() {
    for line in [
        format!("{WORD} tool.sh"),
        format!("{WORD}3 -c 'print(1)'"),
        format!("/usr/bin/{WORD}3"),
        format!("x=$({WORD} -I a.b)"),
        format!("# run {WORD} here"),
        format!("rem {WORD}"),
        format!("Get-Command pwsh,git,{WORD}"),
        format!("\"{WORD}\""),
        format!("{}3.12", WORD.to_ascii_uppercase()),
        format!("{WORD}w script"),
        format!("{WORD}."),
    ] {
        assert!(mentions(&line), "should flag: {line}");
    }
}

#[test]
fn the_matcher_ignores_identifiers_that_only_contain_the_word() {
    for line in [
        format!("fn committed_{WORD}_results()"),
        format!("{WORD}_cases"),
        format!("my{WORD}"),
        format!("{WORD}ic"),
        format!("{WORD}3x"),
        "plain text".to_owned(),
    ] {
        assert!(!mentions(&line), "should not flag: {line}");
    }
}

#[test]
fn shebangs_and_extensions_are_flagged_wherever_the_file_lives() {
    let bad_shebang = format!("#!/usr/bin/env {WORD}3\nprint(1)\n");
    assert_eq!(violations_of("tools/run", bad_shebang.as_bytes()).len(), 2);
    assert!(!violations_of("a/b/c.md", bad_shebang.as_bytes()).is_empty());
    assert_eq!(violations_of(&format!("x.{}", "py"), b"").len(), 1);
    assert!(violations_of("tools/run", b"#!/bin/sh\necho hi\n").is_empty());
    // prose and recorded data are not scanned
    let prose = format!("we no longer use {WORD} here\n");
    assert!(violations_of("README.md", prose.as_bytes()).is_empty());
    assert!(violations_of("env.json", prose.as_bytes()).is_empty());
    // a script mentioning it on any line is flagged, with its line number
    let script = format!("echo ok\n{WORD} x\n");
    assert_eq!(
        violations_of("a.sh", script.as_bytes()),
        vec!["a.sh:2: mentions the banned interpreter".to_owned()]
    );
}

#[test]
fn the_guard_workflow_runs_on_every_change_and_calls_the_shell_guard() {
    let root = repo_root();
    let workflow = fs::read_to_string(root.join(".github/workflows/language-guard.yml")).unwrap();
    for filter in ["paths:", "paths-ignore:", "branches-ignore:"] {
        assert!(
            !workflow.lines().any(|l| l.trim_start().starts_with(filter)),
            "the language guard must not have a `{filter}` filter"
        );
    }
    assert!(workflow.contains("pull_request:") && workflow.contains("push:"));
    assert!(workflow.contains("scripts/language-guard.sh"));
    assert!(root.join("scripts/language-guard.sh").is_file());
}
