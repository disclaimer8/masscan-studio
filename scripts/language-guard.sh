#!/usr/bin/env bash
# Repo-wide language guard: the repository is Rust-only. The tracked tree must contain no
# Swift, C, C++ or Objective-C, or interpreter-script sources, and no use of the banned interpreter.
# Runs on any git work tree (default: the one containing this script), in plain shell so it needs no toolchain.
#
# Fails when
#   1. a tracked file has a banned source extension (any letter case): Swift (.swift),
#      the banned interpreter scripts and notebooks (.py .pyi .pyw .pyc .pyz .ipynb), C, C++ and Objective-C
#      (.c .h .cc .cpp .cxx .c++ .hpp .hh .hxx .h++ .cppm .ixx .m .mm), or is a banned build file (the interpreter's
#      project files: its pyproject, setup.cfg, Pipfile),
#   1b. a tracked SYMLINK has such a name, points at a path with such a name, or points at a file whose first line is a
#      shebang naming the banned interpreter (the link name and every hop of the chain are checked; a target outside
#      the repository is read for its first line only),
#   2. a tracked file starts with a shebang that names the banned interpreter,
#   3. a tracked script or source file (.sh .bash .zsh .ksh .fish .ps1 .cmd .bat .rs .yml
#      .yaml, Makefile*, GNUmakefile*, *.mk, CMakeLists.txt, *.cmake, justfile/Justfile/*.just, or any other file that starts with a shebang)
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

# a path (tracked name or symlink target) with a banned extension or a banned build-file name
banned_name() {
  local base=${1##*/}
  case "$1" in
    *.swift | *.py | *.pyi | *.pyw | *.pyc | *.pyz | *.ipynb | *.c | *.h | *.cc | *.cpp | *.cxx | *.c++ | *.hpp | *.hh | *.hxx | *.h++ | *.cppm | *.ixx | *.m | *.mm) return 0 ;;
  esac
  case "$base" in
    pyproject.toml | setup.cfg | pipfile) return 0 ;;
  esac
  return 1
}

# 1. banned extensions and build files
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if banned_name "$f"; then report "$f: banned source file"; fi
done <<<"$tracked"

# 1b. tracked symlinks: follow the chain by name, read only the first line of the final target
check_link() {
  local f=$1 cur=$1 t hop=0 first
  while [ -L "$cur" ] && [ "$hop" -lt 16 ]; do
    t=$(readlink -- "$cur") || return 0
    if banned_name "$t"; then report "$f: symlink to a banned source file ($t)"; fi
    case "$t" in
      /*) cur=$t ;;
      *) cur=$(dirname -- "$cur")/$t ;;
    esac
    hop=$((hop + 1))
  done
  if [ -f "$cur" ] && [ ! -L "$cur" ]; then
    first=$(head -n 1 -- "$cur" 2>/dev/null | LC_ALL=C tr -d '\0' | head -c 512 || true)
    case "$first" in
      '#!'*)
        if printf '%s\n' "$first" | grep -a -i -E -q -- "$shebang"; then
          report "$f: symlink to a file whose shebang names the banned interpreter ($cur)"
        fi ;;
    esac
  fi
}
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if [ -L "$f" ]; then check_link "$f"; fi
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
    *.sh | *.bash | *.zsh | *.ksh | *.fish | *.ps1 | *.cmd | *.bat | *.rs | *.yml | *.yaml | *.mk | *.cmake | *.just) scan=1 ;;
  esac
  base=${f##*/}
  case "$base" in
    makefile* | gnumakefile* | cmakelists.txt | justfile | .justfile) scan=1 ;;
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
