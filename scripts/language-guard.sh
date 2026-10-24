#!/usr/bin/env bash
# Repo-wide language guard: the repository is Rust-only. The tracked tree must contain no
# Swift, C, C++ or Objective-C, or interpreter-script sources, and no use of the banned interpreter.
# Runs on any git work tree (default: the one containing this script), in plain shell so it needs no toolchain.
#
# Fails when
#   1. a tracked file has a banned source extension (any letter case): Swift (.swift),
#      the banned interpreter scripts (.py .pyw .pyc .pyz), C, C++ and Objective-C (.c .h .cc .cpp .cxx .hpp .hh .m .mm),
#   2. a tracked file starts with a shebang that names the banned interpreter,
#   3. a tracked script or source file (.sh .bash .ps1 .cmd .bat .rs .yml
#      .yaml, Makefile*, GNUmakefile*, *.mk, or any other file that starts with a shebang)
#      mentions the interpreter as a word at all (comments included), or calls the Windows
#      launcher (two letters, then a dash and a version digit; assembled below).
# Prose (.md) and recorded evidence data (.json, .txt, .log, ...) are not scanned.
#
# The banned word is assembled below so that this file does not contain it and
# therefore does not flag itself. tests/rust_only.rs in rmasscan-lab is the same
# policy as a Rust test; keep the two in step.
set -euo pipefail

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$root"

word=py
word="${word}thon"
# word boundary, the word, optional version digits/dots, optional 'w' (windowed
# launcher), word boundary. Case-insensitive via grep -i.
pattern="(^|[^A-Za-z0-9_])${word}[0-9.]*w?([^A-Za-z0-9_]|\$)"
shebang="^#!.*${word}"
# the Windows launcher (name, space, -<digit>); not a longer word, a variable or a path component
lau=p
lau="${lau}y"
launcher="(^|[^A-Za-z0-9_.\$-])${lau}[[:space:]]+-[0-9]"

# bash 3.2 (macOS) has nocasematch: extension and file-name tests ignore letter case
shopt -s nocasematch

fail=0
report() { printf 'FAIL %s\n' "$1"; fail=1; }

tracked=$(git ls-files -z | tr '\0' '\n')

# 1. banned extensions
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    *.swift | *.py | *.pyw | *.pyc | *.pyz | *.c | *.h | *.cc | *.cpp | *.cxx | *.hpp | *.hh | *.m | *.mm)
      report "$f: banned source file" ;;
  esac
done <<<"$tracked"

# 2 and 3. shebangs and word scan
while IFS= read -r f; do
  [ -n "$f" ] || continue
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  first=$(head -n 1 -- "$f" 2>/dev/null | LC_ALL=C tr -d '\0' | head -c 512 || true)
  has_shebang=0
  case "$first" in
    '#!'*) has_shebang=1 ;;
  esac
  if [ "$has_shebang" = 1 ] && printf '%s\n' "$first" | grep -a -i -E -q -- "$shebang"; then
    report "$f:1: shebang names the banned interpreter"
  fi
  scan=$has_shebang
  case "$f" in
    *.sh | *.bash | *.ps1 | *.cmd | *.bat | *.rs | *.yml | *.yaml | *.mk) scan=1 ;;
  esac
  base=${f##*/}
  case "$base" in
    makefile* | gnumakefile*) scan=1 ;;
  esac
  if [ "$scan" = 1 ]; then
    hits=$(grep -a -n -i -E -- "$pattern|$launcher" "$f" 2>/dev/null || true)
    if [ -n "$hits" ]; then
      while IFS= read -r h; do report "$f:${h%%:*}: mentions the banned interpreter"; done <<<"$hits"
    fi
  fi
done <<<"$tracked"

if [ "$fail" -ne 0 ]; then
  echo "language guard: FAILED" >&2
  exit 1
fi
echo "language guard: PASS ($(printf '%s\n' "$tracked" | wc -l | tr -d ' ') tracked files checked)"
