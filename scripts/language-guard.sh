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
#   4. (allowlist) a tracked file is neither a known source/script/build type (rs toml sh bash zsh ksh fish ps1 cmd bat yml yaml md mk
#      cmake just, Makefile*, GNUmakefile*, CMakeLists.txt, justfile), nor known data (json pcap gz txt csv tsv bin lock sha256 log err
#      echo stdout stderr sizes conf rc out diff hex svg png jpg jpeg gif ico icns webp ttf otf woff woff2 pdf html plist pcapng; slint is a source type), nor a listed name (LICENSE*, NOTICE*, COPYING*, AUTHORS*, CODEOWNERS,
#      .gitignore, .gitattributes, .gitkeep, .editorconfig), README*, CHANGELOG*, rust-toolchain, .cargo/config, nor an extensionless script whose shebang is a shell. Any other
#      language source (any extension not listed above) therefore fails,
#   5. a scanned file runs another interpreter language: the five names assembled below as whole words, a complete quoted
#      string naming one, or the JavaScript runtime at a command position; a shebang naming any of them.
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
# the other interpreters, assembled so this file does not contain them as words
strict="pe""rl|ru""by|ph""p|l""ua|lu""ajit|nod""ejs"
rt="nod""e"
all="${strict}|${rt}"
lit_q="[\"']([^\"' ]*/)?(${all})[0-9.]*[\"']"
lit_any="[\"']([^\"' ]*/)?(${all})[0-9.]*[\"']"
lit_rs="((^|[^[])${lit_q}([^:]|\$)|\\[${lit_q}([^]:]|\$))"
quoted_cmd="[\"'][[:space:]]*(/[^[:space:]\"']*/)?(${all})[0-9.]*[[:space:]]+-"
cmd_pos="(^|[;&|(\`{]|(^|[[:space:]])(env|sudo|exec|nohup|xargs|time)[[:space:]]+|run:[[:space:]]+)[[:space:]]*(/[^[:space:]]*/)?(${all})[0-9.]*([[:space:]]|\$|;|\\)|&|\\|)"
shebang_other="^#!.*(${strict}|${rt})"

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

# the allowlist (section 4): a name is allowed by its extension or by being a listed file name
allowed_name() {
  local base=${1##*/}
  case "$1" in
    .cargo/config | */.cargo/config) return 0 ;;
  esac
  case "$base" in
    README* | CHANGELOG* | rust-toolchain | LICENSE* | NOTICE* | COPYING* | AUTHORS* | CODEOWNERS | makefile* | gnumakefile* | cmakelists.txt | justfile | .justfile) return 0 ;;
    .gitignore | .gitattributes | .gitkeep | .editorconfig) return 0 ;;
  esac
  case "$base" in
    ?*.rs | ?*.toml | ?*.sh | ?*.bash | ?*.zsh | ?*.ksh | ?*.fish | ?*.ps1 | ?*.cmd | ?*.bat | ?*.yml | ?*.yaml | ?*.md | ?*.mk | ?*.cmake | ?*.just | ?*.slint) return 0 ;;
    ?*.json | ?*.pcap | ?*.gz | ?*.txt | ?*.csv | ?*.tsv | ?*.bin | ?*.lock | ?*.sha256 | ?*.log | ?*.err | ?*.echo | ?*.stdout | ?*.stderr) return 0 ;;
    ?*.sizes | ?*.conf | ?*.rc | ?*.out | ?*.diff | ?*.hex | ?*.svg | ?*.png | ?*.jpg | ?*.jpeg | ?*.gif | ?*.ico | ?*.icns | ?*.webp | ?*.ttf | ?*.otf | ?*.woff | ?*.woff2 | ?*.pdf | ?*.html | ?*.plist | ?*.pcapng) return 0 ;;
  esac
  return 1
}
# a symlink target name that has an extension the allowlist does not know
ext_not_allowed() {
  local base=${1##*/}
  case "$base" in
    ?*.*) allowed_name "$1" && return 1 || return 0 ;;
  esac
  return 1
}
# the interpreter named by a shebang line is a shell (sh, bash, ...; also through env)
shebang_is_shell() {
  local line=${1#\#!} w prog
  local -a words
  read -r -a words <<<"$line" || true
  [ "${#words[@]}" -gt 0 ] || return 1
  prog=${words[0]##*/}
  if [ "$prog" = env ]; then
    prog=""
    for w in "${words[@]:1}"; do
      case "$w" in -*) continue ;; esac
      prog=${w##*/}
      break
    done
  fi
  case "$prog" in
    sh | bash | zsh | ksh | dash | fish | pwsh) return 0 ;;
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
    if banned_name "$t" || ext_not_allowed "$t"; then report "$f: symlink to a banned source file ($t)"; fi
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
        if printf '%s\n' "$first" | grep -a -i -E -q -- "$shebang|$shebang_other"; then
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
  if [ "$has_shebang" = 1 ] && printf '%s\n' "$first" | grep -a -i -E -q -- "$shebang_other"; then
    report "$f:1: shebang names another banned interpreter"
  fi
  if ! allowed_name "$f"; then
    if [ "$has_shebang" = 1 ] && shebang_is_shell "$first"; then
      :
    elif [ "$has_shebang" = 1 ] && printf '%s\n' "$first" | grep -a -i -E -q -- "$shebang|$shebang_other"; then
      :
    elif banned_name "$f"; then
      :
    else
      report "$f: file type is on neither the source nor the data allowlist (extend allowed_name here and name_allowed in rmasscan-lab/tests/rust_only.rs)"
    fi
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
    # a name in a comment, a prose line, an identifier or (in Rust) an index/map key is not a command
    case "$f" in
      *.rs)
        ohits=$(grep -a -n -i -E -- "$lit_rs|$quoted_cmd" "$f" 2>/dev/null | grep -a -v -E -- '^[0-9]+:[[:space:]]*//' || true) ;;
      *)
        ohits=$(grep -a -n -i -E -- "$lit_any|$quoted_cmd|$cmd_pos" "$f" 2>/dev/null | grep -a -v -i -E -- '^[0-9]+:[[:space:]]*(#|rem[[:space:]]|::)' || true) ;;
    esac
    if [ -n "$ohits" ]; then
      while IFS= read -r h; do [ -n "$h" ] && report "$f:${h%%:*}: runs another banned interpreter language"; done <<<"$ohits"
    fi
  fi
done <<<"$tracked"

if [ "$fail" -ne 0 ]; then
  echo "language guard: FAILED" >&2
  exit 1
fi
echo "language guard: PASS ($(printf '%s\n' "$tracked" | wc -l | tr -d ' ') tracked files checked)"
