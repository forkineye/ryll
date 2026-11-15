#!/usr/bin/env bash
# wave0-scan.sh -- MERGE-TEMPLATE.md's Wave 0 scanners, run over a
# contributor's commits as data.
#
# Everything this executes comes from BASE (origin/develop unless
# WAVE0_BASE says otherwise): BASE's own copy of check-bidi.sh, the
# gitleaks and skillsaw revs BASE pins in .pre-commit-config.yaml, and
# BASE's .gitleaksignore and skillsaw configuration. The contributor's
# REF is only ever read -- as git history, and as a detached checkout
# that the scanners read files from and never run anything from. A fork
# can edit tools/, .pre-commit-config.yaml, .gitleaks.toml,
# .gitleaksignore, .skillsaw.yaml and .gitattributes, and a .skillsaw.yaml
# can name Python files for skillsaw to import, so running any of those
# from the contributor's tree, or reading history with its attributes,
# would let the contributor choose what runs and what passes.
#
# Run it before checking out, building or approving CI on the branch.
# Fetching the script through `git show` means the copy that runs is
# BASE's even when the current checkout is the contributor's branch:
#
#   git fetch origin develop
#   bash <(git show origin/develop:tools/wave0-scan.sh) <ref>
#
# It prints the control files the branch changes first, because those
# are what decide what `make` and CI would run, and they have to be read
# by eye before either. It then runs the scanners and summarises.
#
# Needs git, GNU grep (for -P) and xargs (for -r), pre-commit, and
# network access the first time pre-commit builds the gitleaks and
# skillsaw environments; it checks for the tools before scanning, so a
# missing one is a usage error rather than a finding. That means a Linux
# host or the devcontainer. tools/test-wave0-scan.sh pins its
# behaviour, and CI's skillsaw job runs that test.
#
# Usage: wave0-scan.sh REF
# Exit code: 0 every scanner clean, 1 any scanner found something,
#            2 usage error or nothing to scan.

# The scanners are functions called through check() and the trap, and
# that indirection hides them, so their bodies read as unreachable.
# shellcheck disable=SC2317,SC2329

set -uo pipefail

die() {
    echo "wave0-scan: $*" >&2
    exit 2
}

[ $# -eq 1 ] || die "usage: wave0-scan.sh REF"
command -v git >/dev/null || die "git is not installed"
command -v pre-commit >/dev/null || die "pre-commit is not installed"
printf 'x\n' | grep -qP 'x' 2>/dev/null || die "grep does not support -P; GNU grep is needed"
xargs -r true </dev/null 2>/dev/null || die "xargs does not support -r; GNU xargs is needed"

BASE_REF="${WAVE0_BASE:-origin/develop}"
BASE="$(git rev-parse --verify --quiet "${BASE_REF}^{commit}")" \
    || die "cannot resolve base ${BASE_REF}"
HEAD_SHA="$(git rev-parse --verify --quiet "$1^{commit}")" \
    || die "cannot resolve ${1}"
RANGE="${BASE}..${HEAD_SHA}"

# An empty range would make every scanner below pass having read
# nothing, which is the one outcome this must never report as clean.
COUNT="$(git rev-list --count "$RANGE")"
[ "$COUNT" -gt 0 ] || die "${1} has no commits that ${BASE_REF} lacks"

WORK="$(mktemp -d)"
cleanup() {
    git worktree remove --force "$WORK/base" >/dev/null 2>&1
    git worktree remove --force "$WORK/pr" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# With hooks off: a post-checkout hook installed by pre-commit would
# read the new checkout's .pre-commit-config.yaml, the contributor's.
git -c core.hooksPath=/dev/null worktree add --quiet --detach "$WORK/base" "$BASE" \
    || die "cannot check out ${BASE_REF}"
git -c core.hooksPath=/dev/null worktree add --quiet --detach "$WORK/pr" "$HEAD_SHA" \
    || die "cannot check out ${1}"

echo "Scanning ${COUNT} commit(s): ${BASE_REF} (${BASE:0:12}) .. ${1} (${HEAD_SHA:0:12})"

# What a fork would edit to change what make or CI runs, or what a
# scanner reports. ci.yml's header and MERGE-TEMPLATE.md's "Lane
# changes" row point here rather than keeping lists of their own.
# .gitattributes can mark a file -diff, which turns its patch into
# "Binary files differ" for anything reading history in that checkout;
# .envrc and .vscode/ run on the operator's machine when the review
# worktree is opened in a shell with direnv or in an editor.
CONTROL_PATHS=(
    .github/ tools/ scripts/ .devcontainer/ Makefile .cargo/
    .pre-commit-config.yaml .gitleaks.toml .gitleaksignore
    .skillsaw.yaml .skillsaw.yml .claudelint.yaml .claudelint.yml
    deny.toml clippy.toml rust-toolchain rust-toolchain.toml
    ':(glob)**/.gitattributes' .gitmodules .envrc .vscode/
)
BUILD_PATHS=(':(glob)**/build.rs' ':(glob)**/Cargo.toml' Cargo.lock)

echo
echo "== Control files changed (read every one by eye before make or CI) =="
CONTROL="$(git diff --stat "${BASE}...${HEAD_SHA}" -- "${CONTROL_PATHS[@]}")"
echo "${CONTROL:-none}"
echo
echo "== Build scripts and dependencies changed (read by eye) =="
BUILD="$(git diff --stat "${BASE}...${HEAD_SHA}" -- "${BUILD_PATHS[@]}")"
echo "${BUILD:-none}"

FAILED=()
check() {
    local name="$1"
    shift
    echo
    echo "== ${name} =="
    if "$@"; then
        echo "-- ${name}: clean"
    else
        echo "-- ${name}: FINDINGS"
        FAILED+=("$name")
    fi
}

# The history, every commit's message and patch, is what the
# pattern scans below read: it covers removed lines and lines added
# and later removed again, which a scan of the final files cannot see.
# Plain `git log -p` prints no patch for a merge commit, so content
# that exists only in a merge resolution would be read by nothing.
# --cc prints exactly that content: the hunks where the merge took
# neither parent's version, and not the hunks a routine merge of
# develop brings across unchanged, which would otherwise match this
# script's own patterns. gitleaks below needs a different option.
# --text prints every patch as text: without it, a file the
# contributor's .gitattributes marks -diff, or one with a NUL byte in
# it, prints as "Binary files differ" and none of its lines are read.
git log -p --cc --text --no-textconv --no-ext-diff --format=fuller "$RANGE" \
    > "$WORK/history" || die "cannot read the history of ${RANGE}"
[ -s "$WORK/history" ] || die "the history of ${RANGE} is empty"

BIDI_PATTERN="$(sed -n "s/^PATTERN='\(.*\)'$/\1/p" "$WORK/base/tools/check-bidi.sh")"
[ -n "$BIDI_PATTERN" ] || die "cannot read PATTERN from ${BASE_REF}'s check-bidi.sh"

bidi_files() {
    # check-bidi.sh skips paths that do not exist, so the list is
    # NUL-delimited: a name with a space must not become two misses.
    (cd "$WORK/pr" \
        && git diff -z --name-only --diff-filter=ACMR "${BASE}...${HEAD_SHA}" \
        | xargs -0 -r bash "$WORK/base/tools/check-bidi.sh")
}

no_match() {
    # grep exits 1 on no match, the clean case; 2 is an error, not clean.
    # -a prints a matching line even when the history holds a binary
    # file's bytes, rather than only "binary file matches".
    local rc=0
    LC_ALL=C.UTF-8 grep -anP "$1" "$WORK/history" || rc=$?
    [ "$rc" -eq 1 ]
}

# Prompt-injection shapes are dumb but unfoolable.
INJECTION='(?i)ignore (all )?(previous|prior|above) (instructions|prompts)|disregard (previous|prior) (instructions|prompts)|system: *you are|you are now|new instructions:'

hook_rev() {
    awk -v repo="$1" '
        $1 == "-" && $2 == "repo:" { inrepo = ($3 == repo) }
        inrepo && $1 == "rev:" { print $2; exit }
    ' "$WORK/base/.pre-commit-config.yaml"
}
GITLEAKS_REV="$(hook_rev https://github.com/gitleaks/gitleaks)"
SKILLSAW_REV="$(hook_rev https://github.com/stbenjam/skillsaw)"
[ -n "$GITLEAKS_REV" ] || die "no gitleaks rev in ${BASE_REF}'s .pre-commit-config.yaml"
[ -n "$SKILLSAW_REV" ] || die "no skillsaw rev in ${BASE_REF}'s .pre-commit-config.yaml"
echo
echo "Using gitleaks ${GITLEAKS_REV} and skillsaw ${SKILLSAW_REV}, as ${BASE_REF} pins them."

# The upstream gitleaks hook scans the index (--staged), so on a
# checkout with nothing staged it passes having read nothing. The entry
# is overridden to scan the range instead, at the pinned rev. gitleaks
# runs `git log -p` itself, so merge resolutions are as invisible to it
# as to the history above, and it parses --cc's combined format as an
# empty diff: it reports no leaks whatever the merge holds. Diffing
# each merge against its first parent is a format it reads, and covers
# everything a merge added to the branch -- including, on a merge of an
# older develop, develop's own changes, so a finding attributed to a
# merge commit may be one develop already carries. An inline
# gitleaks:allow silences the finding on its line whatever the
# configuration says, so --ignore-gitleaks-allow turns it off: a
# contributor's allow comment cannot hide a key, and one in prose, with
# no key on its line, is not a finding. --text is as for the history.
cat > "$WORK/pre-commit.yaml" <<EOF
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: ${GITLEAKS_REV}
    hooks:
      - id: gitleaks
        entry: gitleaks git --redact --verbose --no-banner --ignore-gitleaks-allow '--log-opts=--text --diff-merges=first-parent ${RANGE}'
  - repo: https://github.com/stbenjam/skillsaw
    rev: ${SKILLSAW_REV}
    hooks:
      - id: skillsaw
        entry: skillsaw lint --no-custom-rules
EOF

run_hook() {
    # pre-commit exits 0 for a hook it skipped because no file matched,
    # which would read here as a clean scan of nothing. Only its Passed
    # line says the hook ran.
    local out rc=0
    out="$(pre-commit run -c "$WORK/pre-commit.yaml" "$1" --all-files 2>&1)" || rc=$?
    printf '%s\n' "$out"
    [ "$rc" -eq 0 ] || return 1
    if ! grep -q 'Passed$' <<<"$out"; then
        echo "wave0-scan: pre-commit did not run $1, so it scanned nothing"
        return 1
    fi
}

gitleaks_range() {
    # Run from BASE's checkout, so gitleaks reads BASE's .gitleaks.toml,
    # .gitleaksignore and .gitattributes rather than the contributor's.
    (cd "$WORK/base" && run_hook gitleaks)
}

skillsaw_tree() {
    # skillsaw lints a tree, so it has to read the contributor's. Its
    # configuration is found by walking up from there, so swap BASE's in
    # for the contributor's; --no-custom-rules stops it importing Python
    # a configuration names, whichever one is found. --all-files is
    # required, not incidental: without it pre-commit stashes unstaged
    # changes, which would put the contributor's configuration back
    # before the hook runs.
    local f
    for f in .skillsaw.yaml .skillsaw.yml .claudelint.yaml .claudelint.yml; do
        rm -f "$WORK/pr/$f"
        if [ -f "$WORK/base/$f" ]; then
            cp "$WORK/base/$f" "$WORK/pr/$f"
        fi
    done
    (cd "$WORK/pr" && run_hook skillsaw)
}

check "Unicode controls in changed files (check-bidi.sh)" bidi_files
check "Unicode controls in messages and patches" no_match "$BIDI_PATTERN"
check "Prompt-injection shapes" no_match "$INJECTION"
check "Credentials (gitleaks)" gitleaks_range
check "Agent context (skillsaw)" skillsaw_tree

echo
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "wave0-scan: findings from: $(IFS=,; echo "${FAILED[*]}")"
    exit 1
fi
echo "wave0-scan: every scanner clean; the by-eye reviews above still apply."
exit 0
