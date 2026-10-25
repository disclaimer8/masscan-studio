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
    "mk", "cmake", "just", "slint",
];
/// Recorded evidence and other data. Nothing in these is executed or scanned.
const DATA_EXTENSIONS: &[&str] = &[
    "json", "pcap", "gz", "txt", "csv", "tsv", "bin", "lock", "sha256", "log", "err", "echo",
    "stdout", "stderr", "sizes", "conf", "rc", "out", "diff", "hex", "svg", "png", "jpg", "jpeg",
    "gif", "ico", "icns", "webp", "ttf", "otf", "woff", "woff2", "pdf", "plist", "pcapng",
];
/// File names without a usable extension that the tree may hold (matched in lower case; a trailing `*`
/// means prefix).
const ALLOWED_NAMES: &[&str] = &[
    "rust-toolchain",
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
    let lower_base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    // Conventional documents: the bare name, `-MIT` style suffixes, or `.md` / `.txt`; never another extension.
    for p in [
        "license",
        "readme",
        "changelog",
        "notice",
        "copying",
        "authors",
    ] {
        if let Some(rest) = lower_base.strip_prefix(p) {
            let rest = rest
                .strip_suffix(".md")
                .or_else(|| rest.strip_suffix(".txt"))
                .unwrap_or(rest);
            if rest.is_empty() || (rest.starts_with(['-', '_']) && !rest.contains('.')) {
                return true;
            }
        }
    }
    if rel == ".cargo/config" || rel.ends_with("/.cargo/config") {
        return true;
    }
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

/// `s` is one of the interpreters: an optional directory, the name, an optional `.exe`, version digits and dots.
fn is_interpreter_token(s: &str, names: &[&str]) -> bool {
    let base = s.rsplit(['/', '\\']).next().unwrap_or(s);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    names.contains(&base)
}

/// Words that run the next word as a command (shell keywords and wrappers, PowerShell `Start-Process`, cmd
/// `call`, `find -exec`, a YAML `run:`), whatever their options.
const WRAPPERS: &[&str] = &[
    "then",
    "do",
    "else",
    "elif",
    "if",
    "while",
    "until",
    "time",
    "nohup",
    "exec",
    "xargs",
    "env",
    "command",
    "builtin",
    "sudo",
    "timeout",
    "nice",
    "call",
    "start-process",
    "-exec",
    "-execdir",
    "run:",
];

/// Tokens of a script line: whitespace and `;&|(){}` backtick split, and a token that follows `;&|({`
/// backtick `!` (or opens the line) starts a command.
fn command_tokens(lower: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let (mut cur, mut starts) = (String::new(), true);
    let mut flush = |cur: &mut String, starts: &mut bool, next_starts: bool| {
        if !cur.is_empty() {
            out.push((std::mem::take(cur), *starts));
            *starts = next_starts;
        } else if next_starts {
            *starts = true;
        }
    };
    for c in lower.chars() {
        match c {
            c if c.is_whitespace() => flush(&mut cur, &mut starts, false),
            ';' | '&' | '|' | '(' | '{' | '`' | '!' => flush(&mut cur, &mut starts, true),
            ')' | '}' => flush(&mut cur, &mut starts, false),
            c => cur.push(c),
        }
    }
    flush(&mut cur, &mut starts, false);
    out
}

/// After a wrapper: its option words (`-n`, `-u root`, a duration, `VAR=value`, the `ip netns exec NS` words).
fn skip_wrapper_options(t: &[(String, bool)], mut j: usize) -> usize {
    while j < t.len() {
        let w = t[j].0.as_str();
        let flag = w.starts_with('-') && w != "-exec" && w != "-execdir";
        let duration = w.chars().next().is_some_and(|c| c.is_ascii_digit())
            && w.chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == 's' || c == 'm');
        let assignment = w.contains('=') && !w.starts_with('=');
        if flag || duration || assignment {
            j += 1;
        } else {
            break;
        }
    }
    j
}

/// An interpreter name where a command is expected: at the start of a command, or after one or more
/// wrappers (`sudo -n NAME`, `timeout 5 NAME`, `env A=b NAME`, `ip netns exec NS NAME`, `then NAME`).
fn interpreter_run_in_script(lower: &str, names: &[&str]) -> bool {
    let t = command_tokens(lower);
    for i in 0..t.len() {
        let (w, starts) = (&t[i].0, t[i].1);
        let ip_netns = w == "ip"
            && t.get(i + 1).is_some_and(|x| x.0 == "netns")
            && t.get(i + 2).is_some_and(|x| x.0 == "exec");
        let wrapper = ip_netns || WRAPPERS.contains(&w.as_str());
        if !(starts || wrapper) {
            continue;
        }
        let mut j = i;
        let mut wrapped = false;
        loop {
            let is_ip_netns = t[j].0 == "ip"
                && t.get(j + 1).is_some_and(|x| x.0 == "netns")
                && t.get(j + 2).is_some_and(|x| x.0 == "exec");
            if is_ip_netns {
                j += 4;
                wrapped = true;
            } else if WRAPPERS.contains(&t[j].0.as_str()) {
                j = skip_wrapper_options(&t, j + 1);
                wrapped = true;
            } else {
                break;
            }
            if j >= t.len() {
                break;
            }
        }
        if (starts || wrapped) && j < t.len() {
            if is_interpreter_token(&t[j].0, names) {
                return true;
            }
            // `sudo -u root NAME`: a plain word after an option is that option's argument
            let flag_before = j > i && t[j - 1].0.starts_with('-');
            let plain = t[j]
                .0
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                && !t[j].0.starts_with('-');
            if wrapped
                && flag_before
                && plain
                && j + 1 < t.len()
                && is_interpreter_token(&t[j + 1].0, names)
            {
                return true;
            }
        }
    }
    false
}

/// A complete quoted string that is one of the interpreters (scripts and workflows).
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
        if !content.contains(' ') && is_interpreter_token(content, names) {
            return true;
        }
    }
    false
}

/// A quoted command string that starts with an interpreter and an option: `"NAME -e ..."`.
fn quoted_command(lower: &str, names: &[&str]) -> bool {
    let b = lower.as_bytes();
    for (i, q) in b.iter().enumerate() {
        if *q != b'"' && *q != b'\'' {
            continue;
        }
        let rest = lower[i + 1..].trim_start();
        let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        if is_interpreter_token(&rest[..token_end], names)
            && rest[token_end..].trim_start().starts_with('-')
        {
            return true;
        }
    }
    false
}

/// The Rust invocation forms: `Command::new("NAME")`, `.arg("NAME")` / `.args("NAME")`, and an array literal whose
/// first element is `"NAME"` (also a one-element array). A name used as a match pattern, an index, a map key or a
/// compared value is none of these.
fn rust_invocation(lower: &str, names: &[&str]) -> bool {
    let name_at = |from: usize| -> bool {
        let rest = lower[from..].trim_start();
        let Some(rest) = rest.strip_prefix('"') else {
            return false;
        };
        rest.find('"')
            .is_some_and(|e| !rest[..e].contains(' ') && is_interpreter_token(&rest[..e], names))
    };
    for marker in ["command::new(", ".arg(", ".args("] {
        let mut from = 0;
        while let Some(at) = lower[from..].find(marker) {
            let start = from + at + marker.len();
            if name_at(start) {
                return true;
            }
            from = start;
        }
    }
    let b = lower.as_bytes();
    for (i, c) in b.iter().enumerate() {
        if *c != b'[' {
            continue;
        }
        // an index follows an identifier, `)` or `]`; an array literal follows anything else
        let before = lower[..i].chars().next_back();
        if before.is_some_and(|p| p.is_ascii_alphanumeric() || p == '_' || p == ')' || p == ']') {
            continue;
        }
        if name_at(i + 1) {
            return true;
        }
    }
    false
}

/// Whole-line comments are prose: `//` in Rust, `#`, `rem` or `::` in scripts and workflows.
fn comment_line(line: &str, rust: bool) -> bool {
    let t = line.trim_start().to_ascii_lowercase();
    if rust {
        t.starts_with("//")
    } else {
        t.starts_with('#') || t.starts_with("rem ") || t.starts_with("::")
    }
}

/// Another interpreter being RUN on one line of a scanned file (see `rust_invocation` and
/// `interpreter_run_in_script`). Names in comments, prose, identifiers, patterns and comparisons are not flagged.
fn other_interpreter_hit(line: &str, rust: bool) -> bool {
    if comment_line(line, rust) {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    let mut all: Vec<&str> = OTHER_STRICT.to_vec();
    all.push(NODE);
    if rust {
        rust_invocation(&lower, &all) || quoted_command(&lower, &all)
    } else {
        quoted_interpreter(&lower, &all)
            || quoted_command(&lower, &all)
            || interpreter_run_in_script(&lower, &all)
    }
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
    if ext == "svg" && text.to_ascii_lowercase().contains("<script") {
        found.push(format!("{rel}: svg embeds a script"));
    }
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
            "{rel}: file type is on neither the source nor the data allowlist (extend name_allowed here and allowed_name in scripts/language-guard.sh)"        ));
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

// ---- fix round 2 (re-review N5): wider allowlist, fewer false positives, real invocations still caught ----

#[cfg(unix)]
#[test]
fn the_allowlist_accepts_ui_images_fonts_documents_and_conventional_names() {
    let files: Vec<(&str, String)> = vec![
        ("ui/main.slint", "export component A {}\n".into()),
        ("assets/a.jpg", String::new()),
        ("assets/a.jpeg", String::new()),
        ("assets/a.gif", String::new()),
        ("assets/a.ico", String::new()),
        ("assets/a.icns", String::new()),
        ("assets/a.ttf", String::new()),
        ("assets/a.otf", String::new()),
        ("assets/a.woff", String::new()),
        ("assets/a.woff2", String::new()),
        ("docs/a.pdf", String::new()),
        ("macos/Info.plist", "<plist/>\n".into()),
        ("README", "x\n".into()),
        ("CHANGELOG", "x\n".into()),
        ("AUTHORS", "x\n".into()),
        ("COPYING", "x\n".into()),
        ("rust-toolchain", "1.99.1\n".into()),
        (".cargo/config", "[build]\n".into()),
    ];
    assert_eq!(both_guards("allowlist-wide", &files), 0);
    // still closed to everything else
    for name in ["ui/a.qml", "x/a.vue", "x/a.sql", "bin/blob"] {
        assert_eq!(
            both_guards(
                "still-closed",
                &[("ok.sh", "echo ok\n".into()), (name, String::new())]
            ),
            1,
            "{name}"
        );
    }
}

#[cfg(unix)]
#[test]
fn identifiers_index_keys_and_comments_are_not_invocations_but_real_ones_still_are() {
    let clean: Vec<(&str, String)> = vec![
        (
            "a.rs",
            format!(
                "fn f(v: &Value) {{ let n = &v[\"{IN}\"]; let m = json!({{\"{IN}\": 1}}); }}\n"
            ),
        ),
        (
            "b.rs",
            format!("// a {ID}-style table, {IB} on the guest, {IA} and {IC}\n"),
        ),
        ("c.sh", format!("# {IA} is not used here\necho {IN}\n")),
        ("d.yml", format!("# {IN} setup\nname: x\n")),
    ];
    assert_eq!(both_guards("not-invocations", &clean), 0);
    let bad: Vec<(&str, &str, String)> = vec![
        ("arg", "e.rs", format!("c.arg(\"{IA}\");\n")),
        ("new", "e.rs", format!("Command::new(\"{IN}\");\n")),
        (
            "qcmd-rs",
            "e.rs",
            format!("let c = \"{IA} -e 'print 1'\";\n"),
        ),
        ("qcmd-sh", "e.sh", format!("ssh host \"{IB} -e x\"\n")),
        ("pos-sh", "e.sh", format!("x=1; {IC} -r 'echo 1;'\n")),
        ("pipe-sh", "e.sh", format!("cat f | {IN} -p x\n")),
        ("bat", "e.cmd", format!("{ID} script\r\n")),
        ("shebang", "tools/t", format!("#!/usr/bin/env {IB}\n")),
    ];
    for (tag, name, text) in bad {
        let rc = both_guards(tag, &[("ok.sh", "echo ok\n".into()), (name, text)]);
        assert_eq!(rc, 1, "{tag}");
    }
}

// ---- fix round 3 (R2-2, R2-3): every invocation form, on both guards ----

#[cfg(unix)]
#[test]
fn every_invocation_form_of_another_interpreter_fails_both_guards() {
    let n = [IA, IB, IC, ID, IN];
    for name in n {
        let bad: Vec<(&str, String)> = vec![
            ("e.sh", format!("if true; then {name} -e 1; fi\n")),
            ("e.sh", format!("for f in a; do {name} $f; done\n")),
            ("e.sh", format!("if x; then y; else {name} -e 1; fi\n")),
            ("e.sh", format!("a && {name} -e 1\n")),
            ("e.sh", format!("a || {name} -e 1\n")),
            ("e.sh", format!("a | {name} -e 1\n")),
            ("e.sh", format!("a; {name} -e 1\n")),
            ("e.sh", format!("sudo -n {name} -e 1\n")),
            ("e.sh", format!("sudo -u root {name} -e 1\n")),
            ("e.sh", format!("timeout 5 {name} x\n")),
            ("e.sh", format!("env A=b {name} x\n")),
            ("e.sh", format!("nice -n 5 {name} x\n")),
            ("e.sh", format!("exec {name} x\n")),
            ("e.sh", format!("xargs {name} -e x\n")),
            ("e.sh", format!("find . -exec {name} -pi -e x {{}} +\n")),
            ("e.sh", format!("ip netns exec ns {name} -e 1\n")),
            ("e.sh", format!("sudo -n ip netns exec ns {name} -e 1\n")),
            ("e.sh", format!("/usr/bin/{name} -e 1\n")),
            ("e.ps1", format!("{name}.exe -e 1\n")),
            ("e.ps1", format!("Start-Process {name} -ArgumentList x\n")),
            ("e.ps1", format!("& {name} x\n")),
            ("e.cmd", format!("call {name} x\r\n")),
            ("e.cmd", format!("{name}.exe x\r\n")),
            ("e.yml", format!("run: {name} build\n")),
            ("e.rs", format!("Command::new(\"{name}\");\n")),
            ("e.rs", format!("Command::new(\"{name}.exe\");\n")),
            ("e.rs", format!("Command::new(\"/usr/bin/{name}\");\n")),
            ("e.rs", format!("c.arg(\"{name}\");\n")),
            ("e.rs", format!("c.args([\"{name}\", \"x\"]);\n")),
            ("e.rs", format!("let a = [\"{name}\", \"-e\", \"1\"];\n")),
            ("e.rs", format!("let a = [\"{name}\"];\n")),
            ("e.rs", format!("let a = &[\"{name}\"];\n")),
        ];
        for (i, (file, text)) in bad.into_iter().enumerate() {
            let rc = both_guards(
                &format!("form-{i}"),
                &[("ok.sh", "echo ok\n".into()), (file, text.clone())],
            );
            assert_eq!(rc, 1, "both guards must refuse {file}: {text}");
        }
    }
}

#[cfg(unix)]
#[test]
fn match_arms_comparisons_indexes_and_prose_are_not_invocations() {
    let clean: Vec<(&str, String)> = vec![
        (
            "a.rs",
            format!("match s {{ \"{IN}\" => 1, \"{IA}\" | \"{IB}\" => 2, _ => 0 }}\n"),
        ),
        (
            "b.rs",
            format!("assert_eq!(lang, \"{ID}\");\nif x == \"{IC}\" {{ y(); }}\n"),
        ),
        (
            "c.rs",
            format!("let a = v[\"{IN}\"]; let b = w[0][\"{IA}\"]; let c = f()[\"{IB}\"];\n"),
        ),
        ("d.rs", format!("let m = json!({{\"{IN}\": 1}});\n")),
        (
            "e.sh",
            format!("echo the {IN} is up\ngrep {IA} notes.txt\ncp {IB} out\n"),
        ),
        ("f.ps1", format!("Write-Output \"{IN} count\"\n")),
        ("g.cmd", format!("echo {IA}\r\n")),
        ("h.yml", format!("name: {IN} setup\nrun: echo {IA}\n")),
    ];
    assert_eq!(both_guards("not-invocations-2", &clean), 0);
}

#[cfg(unix)]
#[test]
fn conventional_document_names_take_no_other_extension_and_svg_takes_no_script() {
    for name in [
        "README.js",
        "LICENSE.rb",
        "docs/NOTICE.go",
        "CHANGELOG.ts",
        "AUTHORS.pl",
        "COPYING.html",
        "docs/a.html",
    ] {
        assert_eq!(
            both_guards(
                "doc-ext",
                &[("ok.sh", "echo ok\n".into()), (name, String::new())]
            ),
            1,
            "{name}"
        );
    }
    let ok: Vec<(&str, String)> = vec![
        ("README", "x\n".into()),
        ("README.md", "x\n".into()),
        ("LICENSE-MIT", "x\n".into()),
        ("LICENSE-APACHE.txt", "x\n".into()),
        ("NOTICE.txt", "x\n".into()),
        ("a.svg", "<svg><path d=\"M0 0\"/></svg>\n".into()),
    ];
    assert_eq!(both_guards("doc-ok", &ok), 0);
    let rc = both_guards(
        "svg-script",
        &[
            ("ok.sh", "echo ok\n".into()),
            ("a.svg", "<svg><script>x()</script></svg>\n".into()),
        ],
    );
    assert_eq!(rc, 1);
}
