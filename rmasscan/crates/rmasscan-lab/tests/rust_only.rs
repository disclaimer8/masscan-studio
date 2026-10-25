//! Language policy for the whole repository (Rust-only): no Swift, C, C++ or Objective-C, or interpreter-script
//! source files, no use of the banned interpreter in any tracked script or source file, and no
//! shebang that names it.
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
/// The Windows launcher (two letters), assembled so this file does not contain a call of it.
const LAUNCHER: &str = concat!("p", "y");
const SCANNED_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "fish", "ps1", "cmd", "bat", "rs", "yml", "yaml", "cmake", "just",
];
/// Build files that are scanned for the interpreter like scripts (recipes that call it).
const SCANNED_BASENAMES: &[&str] = &["cmakelists.txt", "justfile", ".justfile"];
/// Build files of the banned interpreter's own projects: not allowed at all.
const BANNED_BASENAMES: &[&str] = &["pyproject.toml", "setup.cfg", "pipfile"];
/// Sources the Rust-only repository does not allow: Swift, C, C++, Objective-C and the interpreter scripts.
const BANNED_EXTENSIONS: &[&str] = &[
    "swift", "py", "pyi", "pyw", "pyc", "pyz", "ipynb", "c", "h", "cc", "cpp", "cxx", "c++", "hpp",
    "hh", "hxx", "h++", "cppm", "ixx", "m", "mm",
];

/// Source, script, build and prose types the Rust-only repository allows. Scripts and sources among them
/// are scanned (see `SCANNED_EXTENSIONS`); `md` is prose and `toml` is configuration.
const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "toml", "sh", "bash", "zsh", "ksh", "fish", "ps1", "cmd", "bat", "yml", "yaml", "md",
    "mk", "cmake", "just",
];
/// Recorded evidence and other data. Nothing in these is executed or scanned.
const DATA_EXTENSIONS: &[&str] = &[
    "json", "pcap", "gz", "txt", "csv", "tsv", "bin", "lock", "sha256", "log", "err", "echo",
    "stdout", "stderr", "sizes", "conf", "rc", "out", "diff", "hex", "svg", "png",
];
/// File names without a usable extension that the tree may hold (matched in lower case; a trailing `*`
/// means prefix).
const ALLOWED_NAMES: &[&str] = &[
    "license*",
    "notice*",
    "copying*",
    "authors*",
    "codeowners",
    "makefile*",
    "gnumakefile*",
    "cmakelists.txt",
    "justfile",
    ".justfile",
    ".gitignore",
    ".gitattributes",
    ".gitkeep",
    ".editorconfig",
];
/// Shells whose scripts may live in an extensionless file (the shebang names one of them).
const SHELLS: &[&str] = &["sh", "bash", "zsh", "ksh", "dash", "fish", "pwsh"];
/// Other interpreters, assembled so this file does not contain them as words. Whole words in every scanned file.
const OTHER_STRICT: &[&str] = &[
    concat!("pe", "rl"),
    concat!("ru", "by"),
    concat!("ph", "p"),
    concat!("l", "ua"),
    concat!("lu", "ajit"),
    concat!("nod", "ejs"),
];
/// `node` is also an everyday identifier: it is flagged as a string literal and, in shell-like files,
/// at a command position.
const NODE: &str = concat!("no", "de");

fn name_allowed(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    if ALLOWED_NAMES.iter().any(|a| match a.strip_suffix('*') {
        Some(prefix) => base.starts_with(prefix),
        None => base == *a,
    }) {
        return true;
    }
    match base.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            SOURCE_EXTENSIONS.contains(&ext) || DATA_EXTENSIONS.contains(&ext)
        }
        _ => false,
    }
}

/// `name` as a whole word of `lower`, optionally followed by version digits and dots.
fn has_word(lower: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(at) = lower[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        let before_ok = lower[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !word_char(c));
        let rest = lower[end..].trim_start_matches(|c: char| c.is_ascii_digit() || c == '.');
        if before_ok && rest.chars().next().is_none_or(|c| !word_char(c)) {
            return true;
        }
        from = end;
    }
    false
}

/// A complete quoted string that is one of the interpreters, optionally with a directory prefix.
fn quoted_interpreter(lower: &str, names: &[&str]) -> bool {
    let b = lower.as_bytes();
    for (i, q) in b.iter().enumerate() {
        if *q != b'"' && *q != b'\'' {
            continue;
        }
        let Some(len) = lower[i + 1..].find(*q as char) else {
            continue;
        };
        let content = &lower[i + 1..i + 1 + len];
        if content.contains(' ') {
            continue;
        }
        let base = content.rsplit('/').next().unwrap_or(content);
        let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        if names.contains(&base) {
            return true;
        }
    }
    false
}

/// `node` where a command is expected: line start, after `; & | ( { `` ` ``, after env, sudo, exec, nohup,
/// xargs, time or a YAML `run:`.
fn node_at_command_position(lower: &str) -> bool {
    let mut from = 0;
    while let Some(at) = lower[from..].find(NODE) {
        let end = from + at + NODE.len();
        let after = lower[end..].trim_start_matches(|c: char| c.is_ascii_digit() || c == '.');
        let after_ok = after
            .chars()
            .next()
            .is_none_or(|c| c.is_whitespace() || matches!(c, ';' | ')' | '&' | '|'));
        // the token that holds it: an optional directory prefix, then the name
        let token_start = lower[..from + at]
            .rfind(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | '{' | '`'))
            .map_or(0, |i| i + 1);
        let token_head = &lower[token_start..from + at];
        let path_ok = token_head.is_empty() || token_head.ends_with('/');
        let before = lower[..token_start].trim_end();
        let last_word = before
            .rsplit(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | '{' | '`'))
            .next()
            .unwrap_or("");
        let command_position = before.is_empty()
            || before.ends_with([';', '&', '|', '(', '{', '`'])
            || ["env", "sudo", "exec", "nohup", "xargs", "time", "run:"].contains(&last_word);
        if after_ok && path_ok && command_position {
            return true;
        }
        from = end;
    }
    false
}

/// The other interpreters on one line of a scanned file. `rust` files get only the forms that cannot
/// be an identifier.
fn other_interpreter_hit(line: &str, rust: bool) -> bool {
    let lower = line.to_ascii_lowercase();
    let mut all: Vec<&str> = OTHER_STRICT.to_vec();
    all.push(NODE);
    OTHER_STRICT.iter().any(|w| has_word(&lower, w))
        || quoted_interpreter(&lower, &all)
        || (!rust && node_at_command_position(&lower))
}

/// A shebang that names one of the other interpreters (whole word or path component).
fn shebang_names_other(first_line: &str) -> bool {
    if !first_line.starts_with("#!") {
        return false;
    }
    let lower = first_line.to_ascii_lowercase();
    OTHER_STRICT
        .iter()
        .chain(std::iter::once(&NODE))
        .any(|w| lower.contains(w))
}

/// The interpreter a shebang runs: the last word of `#!/usr/bin/env -S bash -eu` style lines.
fn shebang_is_shell(first_line: &str) -> bool {
    let words: Vec<&str> = first_line
        .trim_start_matches("#!")
        .split_whitespace()
        .collect();
    let program = |w: &str| w.rsplit('/').next().unwrap_or(w).to_ascii_lowercase();
    match words.first() {
        Some(first) if program(first) == "env" => words
            .iter()
            .skip(1)
            .find(|w| !w.starts_with('-'))
            .is_some_and(|w| SHELLS.contains(&program(w).as_str())),
        Some(first) => SHELLS.contains(&program(first).as_str()),
        None => false,
    }
}

fn repo_root() -> PathBuf {
    // Read at run time: cargo reuses a test binary between checkouts, and `env!` would pin the one that built it.
    let manifest =
        std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR for tests");
    Path::new(&manifest)
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
        if matches!(name.as_str(), ".git" | "target" | "node_modules") {
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

/// The launcher form: the name as a whole token followed by whitespace, `-` and a digit.
fn calls_launcher(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find(LAUNCHER) {
        let start = from + at;
        let end = start + LAUNCHER.len();
        let before_ok = lower[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(word_char(c) || c == '.' || c == '$' || c == '-'));
        let rest = &lower[end..];
        let trimmed = rest.trim_start();
        let spaced = trimmed.len() < rest.len();
        let dash_digit = trimmed
            .strip_prefix('-')
            .and_then(|t| t.chars().next())
            .is_some_and(|c| c.is_ascii_digit());
        if before_ok && spaced && dash_digit {
            return true;
        }
        from = end;
    }
    false
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
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext = ext.as_str();
    let base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    let makefile = base.starts_with("makefile") || base.starts_with("gnumakefile") || ext == "mk";
    if BANNED_EXTENSIONS.contains(&ext) || BANNED_BASENAMES.contains(&base.as_str()) {
        found.push(format!("{rel}: banned source file"));
    }
    let text = String::from_utf8_lossy(bytes);
    let has_shebang = text.starts_with("#!");
    if shebang_names_interpreter(text.lines().next().unwrap_or("")) {
        found.push(format!("{rel}:1: shebang names the banned interpreter"));
    }
    let first_line = text.lines().next().unwrap_or("");
    let other_shebang = shebang_names_other(first_line);
    if other_shebang {
        found.push(format!("{rel}:1: shebang names another banned interpreter"));
    }
    // Final review M-4: the tree is an allowlist, not a denylist of three language families. A file is
    // either a known source or script type, known data, a listed name, or a script whose shebang is a shell.
    if !name_allowed(rel)
        && !(has_shebang && shebang_is_shell(first_line))
        && !(has_shebang && (shebang_names_interpreter(first_line) || other_shebang))
        && !BANNED_EXTENSIONS.contains(&ext)
        && !BANNED_BASENAMES.contains(&base.as_str())
    {
        found.push(format!(
            "{rel}: file type is on neither the source nor the data allowlist"
        ));
    }
    if has_shebang
        || makefile
        || SCANNED_EXTENSIONS.contains(&ext)
        || SCANNED_BASENAMES.contains(&base.as_str())
    {
        for (n, line) in text.lines().enumerate() {
            if mentions(line) || calls_launcher(line) {
                found.push(format!("{rel}:{}: mentions the banned interpreter", n + 1));
            } else if other_interpreter_hit(line, ext == "rs") {
                found.push(format!(
                    "{rel}:{}: runs another banned interpreter language",
                    n + 1
                ));
            }
        }
    }
    found
}

/// Policy violations of a tracked SYMLINK `rel` whose link text is `target`: the target's name is banned, or
/// (when it resolves to a regular file) its first line is a shebang naming the interpreter. The chain is
/// followed hop by hop; only the first line of the final target is read, wherever it lives.
fn link_violations(root: &Path, rel: &str, target: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut cur = root.join(rel);
    let mut text = target.to_owned();
    for _ in 0..16 {
        let lower = text.to_ascii_lowercase();
        let base = lower.rsplit('/').next().unwrap_or("");
        let ext = Path::new(base)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if BANNED_EXTENSIONS.contains(&ext)
            || BANNED_BASENAMES.contains(&base)
            || (!ext.is_empty() && !name_allowed(base))
        {
            found.push(format!("{rel}: symlink to a banned source file ({text})"));
        }
        cur = cur.parent().unwrap_or(Path::new("/")).join(&text);
        match fs::read_link(&cur) {
            Ok(next) => text = next.to_string_lossy().into_owned(),
            Err(_) => break,
        }
    }
    if cur.is_file() {
        use std::io::Read;
        let mut head = Vec::new();
        if let Ok(f) = fs::File::open(&cur) {
            let _ = f.take(512).read_to_end(&mut head);
        }
        let first = String::from_utf8_lossy(&head);
        let line = first.lines().next().unwrap_or("");
        if shebang_names_interpreter(line) || shebang_names_other(line) {
            found.push(format!(
                "{rel}: symlink to a file whose shebang names the banned interpreter"
            ));
        }
    }
    found
}

/// Every violation among the tracked `files` of the tree at `root` (symlinks are checked by name and target).
fn policy_violations(root: &Path, files: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for rel in files {
        let path = root.join(rel);
        if path.is_symlink() {
            found.extend(
                violations_of(rel, b"")
                    .into_iter()
                    .filter(|v| !v.contains("allowlist")),
            );
            if let Ok(t) = fs::read_link(&path) {
                found.extend(link_violations(root, rel, &t.to_string_lossy()));
            }
            continue;
        }
        if !path.is_file() {
            continue;
        }
        found.extend(violations_of(rel, &fs::read(&path).unwrap()));
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
    let found = policy_violations(&root, &files);
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

// ---- LR N3: the shell guard, run against planted temporary repositories ---------------------------

/// Runs `scripts/language-guard.sh` on a fresh git repository holding `files`; returns its rc.
fn guard_rc(tag: &str, files: &[(&str, String)]) -> i32 {
    let dir = std::env::temp_dir().join(format!("rmasscan-guard-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for (name, text) in files {
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    let git = |args: &[&str]| {
        let st = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(args)
            .output()
            .unwrap();
        assert!(st.status.success(), "git {args:?}: {st:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    let guard = repo_root().join("scripts/language-guard.sh");
    let out = Command::new("bash").arg(guard).arg(&dir).output().unwrap();
    let _ = fs::remove_dir_all(&dir);
    out.status.code().unwrap()
}

#[test]
fn the_shell_guard_passes_a_clean_repository_and_ignores_prose() {
    let prose = format!("we no longer use {WORD} here\n");
    assert_eq!(
        guard_rc(
            "clean",
            &[
                ("a.sh", "echo ok\n".into()),
                ("Makefile", "all:\n\tcargo build\n".into()),
                ("docs/x.md", prose),
            ]
        ),
        0
    );
}

#[test]
fn the_shell_guard_catches_case_variants_zipapps_makefiles_and_the_windows_launcher() {
    let call = format!("{WORD}3 tool\n");
    let mut plants: Vec<(String, Vec<(&str, String)>)> = Vec::new();
    for (name, body) in [
        ("lower extension", ("docs/x.py", String::new())),
        ("upper extension", ("docs/X.PY", String::new())),
        ("mixed extension", ("docs/x.Pyw", String::new())),
        ("zipapp", ("docs/app.pyz", String::new())),
        ("upper zipapp", ("docs/app.PYZ", String::new())),
        ("windowed", ("docs/app.pyw", String::new())),
        ("makefile", ("Makefile", format!("all:\n\t{call}"))),
        (
            "makefile variant",
            ("Makefile.lab", format!("all:\n\t{call}")),
        ),
        ("gnumakefile", ("GNUmakefile", format!("all:\n\t{call}"))),
        ("mk include", ("build/rules.mk", format!("run:\n\t{call}"))),
        (
            "launcher ps1",
            ("scripts/b.ps1", format!("{LAUNCHER} -3 tool\n")),
        ),
        (
            "launcher cmd",
            ("scripts/b.cmd", format!("{LAUNCHER} -3 tool\r\n")),
        ),
        (
            "launcher bat",
            (
                "scripts/b.bat",
                format!("@echo off\r\n{LAUNCHER} -3.12 tool\r\n"),
            ),
        ),
        (
            "launcher sh",
            ("scripts/b.sh", format!("{LAUNCHER} -3 tool\n")),
        ),
        (
            "launcher makefile",
            ("Makefile", format!("all:\n\t{LAUNCHER} -3 tool\n")),
        ),
    ] {
        plants.push((name.to_owned(), vec![body]));
    }
    for (name, files) in &plants {
        let tag = name.replace(' ', "-");
        assert_eq!(guard_rc(&tag, files), 1, "guard missed: {name}");
    }
}

#[test]
fn the_shell_guard_does_not_flag_py_as_part_of_other_words() {
    // `py` alone is not the interpreter; only the launcher form `py -<digit>` is.
    assert_eq!(
        guard_rc(
            "py-words",
            &[
                ("a.sh", "echo copy; cp a b\n".into()),
                ("b.ps1", "$pp = 1\nWrite-Output happy -3\n".into()),
            ]
        ),
        0
    );
}

#[test]
fn the_rust_matcher_flags_the_same_additions() {
    assert!(violations_of("docs/X.PY", b"").len() == 1);
    assert!(violations_of("docs/app.pyz", b"").len() == 1);
    assert!(violations_of("docs/app.PyW", b"").len() == 1);
    let call = format!("all:\n\t{WORD}3 tool\n");
    for name in ["Makefile", "Makefile.lab", "GNUmakefile", "build/rules.mk"] {
        assert_eq!(violations_of(name, call.as_bytes()).len(), 1, "{name}");
    }
    for name in ["b.ps1", "b.cmd", "b.bat", "b.sh", "Makefile"] {
        assert_eq!(
            violations_of(name, format!("{LAUNCHER} -3 tool\n").as_bytes()).len(),
            1,
            "{name}"
        );
    }
    assert!(violations_of("b.ps1", b"$p = 1\nhappy -3\ncopy -3\n").is_empty());
}

#[test]
fn banned_source_extensions_are_flagged_in_any_letter_case() {
    for name in [
        "a.swift", "A.SWIFT", "x/y.c", "x/Y.C", "i.h", "i.H", "a.cc", "a.cpp", "a.CXX", "a.hpp",
        "a.hh", "a.m", "a.mm", "a.py", "a.PYZ",
    ] {
        assert_eq!(violations_of(name, b"").len(), 1, "{name}");
    }
    for name in ["a.rs", "a.md", "a.sh", "a.json", "chart.hex", "Cargo.toml"] {
        assert!(violations_of(name, b"").is_empty(), "{name}");
    }
}

#[test]
fn the_shell_guard_fails_on_planted_swift_c_and_cpp_sources() {
    for (tag, name) in [
        ("swift", "Sources/App.swift"),
        ("upper-swift", "Sources/App.SWIFT"),
        ("c", "src/main.c"),
        ("header", "src/main.h"),
        ("cpp", "src/main.cpp"),
        ("objc", "src/main.m"),
    ] {
        let files = [("ok.sh", "echo ok\n".into()), (name, String::new())];
        assert_eq!(guard_rc(tag, &files), 1, "guard missed {name}");
    }
}

// ---- F7: symlinks, more extensions, build files, more shells --------------------------------------

/// Runs the shell guard on a fresh git repository holding `files` and the symlinks `links` (name, link text);
/// returns its rc and output.
#[cfg(unix)]
fn guard_with_links(tag: &str, files: &[(&str, String)], links: &[(&str, &str)]) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("rmasscan-guard-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for (name, text) in files {
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
    for (name, target) in links {
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, p).unwrap();
    }
    let git = |args: &[&str]| {
        let st = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(args)
            .output()
            .unwrap();
        assert!(st.status.success(), "git {args:?}: {st:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    let guard = repo_root().join("scripts/language-guard.sh");
    let out = Command::new("bash").arg(guard).arg(&dir).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let rc = out.status.code().unwrap();
    // the Rust matcher over the same planted tree
    let rust = policy_violations(&dir, &tracked_files(&dir));
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        rc == 1,
        !rust.is_empty(),
        "shell guard (rc {rc}: {text}) and Rust matcher ({rust:?}) disagree on {tag}"
    );
    (rc, text)
}

#[cfg(unix)]
#[test]
fn both_guards_fail_on_tracked_symlinks_to_banned_programs() {
    let bad_shebang = format!("#!/usr/bin/env {WORD}3\n");
    type Case = (
        &'static str,
        Vec<(&'static str, String)>,
        Vec<(&'static str, String)>,
    );
    let cases: Vec<Case> = vec![
        // (tag, files, links as (name, target))
        (
            "link-to-missing-py",
            vec![("ok.sh", "echo ok\n".into())],
            vec![("bin/tool", "../elsewhere/gone.py".into())],
        ),
        (
            "link-to-shebang",
            vec![("tools/real", bad_shebang.clone())],
            vec![("bin/tool", "../tools/real".into())],
        ),
        (
            "link-chain-to-shebang",
            vec![("tools/real", bad_shebang.clone())],
            vec![("bin/a", "../tools/real".into()), ("bin/b", "a".into())],
        ),
        (
            "link-named-py",
            vec![("tools/real", "echo ok\n".into())],
            vec![("bin/tool.py", "../tools/real".into())],
        ),
        (
            "link-to-c",
            vec![("ok.sh", "echo ok\n".into())],
            vec![("bin/x", "../src/main.c".into())],
        ),
    ];
    for (tag, files, links) in cases {
        let links: Vec<(&str, &str)> = links.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let (rc, text) = guard_with_links(tag, &files, &links);
        assert_eq!(rc, 1, "guard missed {tag}: {text}");
    }
}

#[cfg(unix)]
#[test]
fn both_guards_accept_harmless_symlinks() {
    let (rc, text) = guard_with_links(
        "link-ok",
        &[
            ("tools/real.sh", "echo ok\n".into()),
            ("tools/plain", "#!/bin/sh\necho ok\n".into()),
        ],
        &[
            ("bin/a", "../tools/real.sh"),
            ("bin/b", "../tools/plain"),
            ("bin/dangling", "nowhere"),
        ],
    );
    assert_eq!(rc, 0, "{text}");
}

#[test]
fn more_banned_extensions_and_build_files_fail_both_guards() {
    let call = format!("{WORD}3 tool\n");
    for name in [
        "a.pyi",
        "n/a.ipynb",
        "A.IPYNB",
        "a.hxx",
        "a.h++",
        "a.c++",
        "a.cppm",
        "a.ixx",
        "pyproject.toml",
        "sub/setup.cfg",
        "Pipfile",
    ] {
        assert_eq!(violations_of(name, b"").len(), 1, "rust: {name}");
        assert_eq!(
            guard_rc("ext", &[(name, String::new())]),
            1,
            "shell: {name}"
        );
    }
    for name in [
        "CMakeLists.txt",
        "sub/CMakeLists.txt",
        "cmake/run.cmake",
        "justfile",
        "Justfile",
        "tools/.justfile",
        "x.just",
        "a.zsh",
        "a.ksh",
        "a.fish",
    ] {
        assert_eq!(
            violations_of(name, call.as_bytes()).len(),
            1,
            "rust: {name}"
        );
        assert_eq!(
            guard_rc("recipe", &[(name, call.clone())]),
            1,
            "shell: {name}"
        );
        // no interpreter, no finding
        assert!(violations_of(name, b"echo ok\n").is_empty(), "rust: {name}");
        assert_eq!(
            guard_rc("recipe-ok", &[(name, "echo ok\n".into())]),
            0,
            "shell: {name}"
        );
    }
}

/// The target is outside the repository (so it is not itself a tracked file): only the link can be caught.
#[cfg(unix)]
#[test]
fn both_guards_fail_on_a_symlink_to_an_outside_file_with_the_banned_shebang() {
    let outside =
        std::env::temp_dir().join(format!("rmasscan-guard-target-{}", std::process::id()));
    fs::write(&outside, format!("#!/usr/bin/env {WORD}3\nprint(1)\n")).unwrap();
    let target = outside.to_string_lossy().into_owned();
    let (rc, text) = guard_with_links(
        "outside",
        &[("ok.sh", "echo ok\n".into())],
        &[("bin/x", &target)],
    );
    let _ = fs::remove_file(&outside);
    assert_eq!(rc, 1, "guard missed the outside shebang target: {text}");
    assert!(text.contains("bin/x"), "{text}");
}

// ---- final review M-4: the guards are allowlists, and other interpreters are scanned like the first ----

/// Names of the other interpreters, assembled so this file does not contain them as words.
const IA: &str = concat!("pe", "rl");
const IB: &str = concat!("ru", "by");
const IC: &str = concat!("ph", "p");
const ID: &str = concat!("l", "ua");
const IN: &str = concat!("no", "de");

/// Both guards on one planted tree; they must agree. Returns the exit code of the shell guard.
fn both_guards(tag: &str, files: &[(&str, String)]) -> i32 {
    let (rc, text) = guard_with_links(tag, files, &[]);
    assert!(rc == 0 || text.contains("FAIL"), "{text}");
    rc
}

#[cfg(unix)]
#[test]
fn files_of_other_languages_fail_both_guards() {
    for name in [
        format!("tools/x.{}", "pl"),
        format!("tools/x.{}", "pm"),
        format!("web/app.{}", "js"),
        format!("web/app.{}", "mjs"),
        format!("web/app.{}", "ts"),
        format!("cmd/main.{}", "go"),
        format!("src/Main.{}", "java"),
        format!("src/x.{}", "rb"),
        format!("src/x.{ID}"),
        format!("src/x.{IC}"),
        format!("src/x.{}", "tcl"),
        format!("src/X.{}", "JS"),
        "bin/unknown-extensionless".to_owned(),
    ] {
        let rc = both_guards(
            "lang",
            &[("ok.sh", "echo ok\n".into()), (&name, String::new())],
        );
        assert_eq!(rc, 1, "both guards must refuse {name}");
    }
}

#[cfg(unix)]
#[test]
fn the_allowlist_still_accepts_the_files_the_tree_holds() {
    let files: Vec<(&str, String)> = vec![
        ("a.rs", "fn main() {}\n".into()),
        ("Cargo.toml", "[package]\n".into()),
        ("Cargo.lock", String::new()),
        ("run.sh", "echo ok\n".into()),
        ("run.ps1", "Write-Output ok\n".into()),
        ("run.cmd", "echo ok\r\n".into()),
        (".github/workflows/x.yml", "name: x\n".into()),
        ("docs/x.md", "text\n".into()),
        ("ev/a.json", "{}\n".into()),
        ("ev/a.pcap", String::new()),
        ("ev/a.pcap.gz", String::new()),
        ("ev/a.txt", "x\n".into()),
        ("ev/a.csv", "a,b\n".into()),
        ("ev/a.bin", String::new()),
        ("ev/a.sha256", "x\n".into()),
        ("ev/a.err", "x\n".into()),
        ("LICENSE", "x\n".into()),
        ("NOTICE", "x\n".into()),
        (".gitignore", "target\n".into()),
        ("tools/run", "#!/bin/sh\necho ok\n".into()),
        ("tools/run2", "#!/usr/bin/env bash\necho ok\n".into()),
    ];
    assert_eq!(both_guards("allowlist-ok", &files), 0);
}

#[cfg(unix)]
#[test]
fn other_interpreters_are_scanned_like_the_first() {
    let cases: Vec<(&str, &str, String)> = vec![
        (
            "rs-command",
            "src/a.rs",
            format!("fn f() {{ Command::new(\"{IA}\"); }}\n"),
        ),
        (
            "rs-node",
            "src/a.rs",
            format!("fn f() {{ Command::new(\"{IN}\"); }}\n"),
        ),
        ("rs-p", "src/a.rs", format!("let p = \"/usr/bin/{IB}\";\n")),
        ("rs-d", "src/a.rs", format!("// call {ID} here\n")),
        ("sh-a", "run.sh", format!("{IA} -e 'print 1'\n")),
        ("sh-env", "run.sh", format!("env {IB} x\n")),
        ("sh-pipe", "run.sh", format!("cat x | {IC} -r 'echo 1;'\n")),
        ("sh-node", "run.sh", format!("{IN} -e 'x'\n")),
        ("sh-sudo-node", "run.sh", format!("sudo {IN} app\n")),
        ("sh-subshell", "run.sh", format!("x=$({IN} -p 1)\n")),
        ("ps1", "run.ps1", format!("& {IA} x\n")),
        ("yml-run", "w.yml", format!("run: {IN} build\n")),
        (
            "shebang",
            "tools/run",
            format!("#!/usr/bin/env {IA}\nprint 1;\n"),
        ),
        (
            "shebang-node",
            "tools/run",
            format!("#!/usr/bin/env {IN}\n"),
        ),
    ];
    for (tag, name, text) in cases {
        let rc = both_guards(tag, &[("ok.sh", "echo ok\n".into()), (name, text)]);
        assert_eq!(rc, 1, "both guards must refuse {tag}");
    }
}

#[cfg(unix)]
#[test]
fn everyday_uses_of_the_runtime_name_and_prose_are_not_flagged() {
    let files: Vec<(&str, String)> = vec![
        (
            "a.rs",
            format!("fn f() {{ let {IN} = unsafe {{ &*cur }}; {IN}.next = 1; {IN} = x; }}\n"),
        ),
        ("run.sh", format!("echo {IN}\n# a {IN} in a comment\n")),
        (
            "docs/x.md",
            format!("{IA} {IB} {IC} {ID} {IN} are not scanned in prose\n"),
        ),
        ("ev/a.json", format!("{{\"{IN}\":\"{IA}\"}}\n")),
    ];
    assert_eq!(both_guards("everyday", &files), 0);
}
