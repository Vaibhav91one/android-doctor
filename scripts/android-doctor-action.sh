#!/usr/bin/env bash
# Body of the android-doctor GitHub Action (action.yml): install the pinned release binary (or use
# AD_BINARY), scan, write the step summary and the outputs, and exit with the gating status.
#
# Local run: AD_BINARY=target/release/android-doctor AD_PATH=fw AD_OUT=/tmp/ad scripts/android-doctor-action.sh
# Env: AD_PATH (required; words, space separated), AD_COMMAND ("doctor scan" | "audit"),
#      AD_FAIL_ON (error|high|medium|warn|none, default error), AD_BASELINE (a committed --json report),
#      AD_ARGS (extra flags, space separated), AD_VERSION / ACTION_REF (see resolve_version),
#      AD_BINARY (an already-built binary: skips the download), AD_OUT (default: $RUNNER_TEMP or .).
# Exit: 0 clean; 1 findings at or above fail-on; 3 the same under a baseline (only new findings
#      count); otherwise the tool's own failure status (unreadable input, bad flags...).
# ponytail: paths and args are split on spaces, so a path with a space is not supported.
set -uo pipefail

REPO=Vaibhav91one/android-doctor

die() { echo "::error::android-doctor action: $*" >&2; exit 2; }

# The release to install: `version` if given, else the ref the action itself was pinned at.
# Never "latest": an unpinned ref (branch, sha, local checkout) must say which version to install.
resolve_version() {
  local v=${1:-}
  [ -n "$v" ] || v=${2:-}
  v=${v#v}
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] \
    || die "cannot tell which release to install: set the 'version' input (for example 0.2.0), or pin the action at a release tag (uses: $REPO@vX.Y.Z); the ref '${2:-}' is not a release tag. 'latest' is never assumed."
  printf '%s\n' "$v"
}

# Release asset target for `uname -s` / `uname -m` (see .github/workflows/release.yml).
target_for() {
  case "$1/$2" in
    Linux/x86_64) echo x86_64-unknown-linux-gnu ;;
    Darwin/arm64 | Darwin/aarch64) echo aarch64-apple-darwin ;;
    Darwin/x86_64) echo x86_64-apple-darwin ;;
    *) return 1 ;;
  esac
}

sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# Download the pinned release into $1 and print the binary path.
install_release() {
  local dir=$1 version target url tarball want got
  version=$(resolve_version "${AD_VERSION:-}" "${ACTION_REF:-}") || exit 2
  target=$(target_for "$(uname -s)" "$(uname -m)") \
    || die "unsupported runner $(uname -s)/$(uname -m): releases exist for Linux x86_64, macOS arm64 and macOS x86_64. Build the binary yourself and pass it with the 'binary' input."
  url="https://github.com/$REPO/releases/download/v$version/android-doctor-$target.tar.gz"
  mkdir -p "$dir"
  tarball="$dir/android-doctor-$target.tar.gz"
  curl -fsSL --retry 3 -o "$tarball" "$url" || die "cannot download $url (does release v$version exist?)"
  if want=$(curl -fsSL "$url.sha256" 2>/dev/null) && [ -n "$want" ]; then
    got=$(sha256_of "$tarball")
    [ "${want%% *}" = "$got" ] || die "sha256 mismatch for $url: expected ${want%% *}, got $got"
    echo "::notice::android-doctor $version: sha256 verified against the published checksum" >&2
  else
    echo "::notice::android-doctor $version: the release publishes no .sha256 file, so the download is not checksum-verified (it is fetched over HTTPS from the release)" >&2
  fi
  tar xzf "$tarball" -C "$dir" android-doctor || die "unexpected archive layout in $tarball (expected a top-level android-doctor binary)"
  printf '%s\n' "$dir/android-doctor"
}

# severity name -> rank; "none" -> 99 so nothing reaches it.
rank() {
  case $1 in info) echo 0 ;; warn) echo 1 ;; medium) echo 2 ;; high) echo 3 ;; error) echo 4 ;; none) echo 99 ;; *) return 1 ;; esac
}

# gate_status RC FINDINGS_JSON FAIL_ON BASELINE -> prints the status the job should exit with.
# No parsable report means the tool itself failed: its status passes through. Otherwise any
# finding at or above FAIL_ON gates (the report holds only new findings under a baseline, so 3
# there, else 1).
gate_status() {
  local rc=$1 json=$2 fail_on=$3 baseline=$4 min hits
  min=$(rank "$fail_on") || die "fail-on must be one of error, high, medium, warn, none (got '$fail_on')"
  if ! jq -e . "$json" >/dev/null 2>&1; then
    if [ "$rc" -ne 0 ]; then echo "$rc"; else echo 1; fi
    return
  fi
  hits=$(jq --argjson min "$min" '
    def rank: {"info":0,"warn":1,"medium":2,"high":3,"error":4}[.] // 0;
    [(if type == "array" then . else .findings end)[] | select(.severity | rank >= $min)] | length' "$json")
  if [ "$hits" -eq 0 ]; then echo 0; elif [ -n "$baseline" ]; then echo 3; else echo 1; fi
}

# summary JSON SARIF BASELINE_NOTE STATUS FAIL_ON -> markdown on stdout.
summary() {
  local json=$1 sarif=$2 note=$3 status=$4 fail_on=$5 score
  score=$(jq -r '.runs[0].properties.score | "\(.value)/100 (\(.label))"' "$sarif" 2>/dev/null || true)
  echo "### android-doctor"
  echo
  echo "Health score: **${score:-unavailable}**"
  echo
  if jq -e . "$json" >/dev/null 2>&1; then
    echo "| severity | findings |"
    echo "|---|---|"
    jq -r '
      (if type == "array" then . else .findings end) as $f
      | ["error","high","medium","warn","info"][] as $s
      | "| \($s) | \([$f[] | select(.severity == $s)] | length) |"' "$json"
    echo
    if [ -n "$note" ]; then
      echo "Baseline \`${note#baseline }\`. Only new findings are listed and gate."
      echo
    fi
    echo "Top findings:"
    echo
    jq -r '
      def rank: {"info":0,"warn":1,"medium":2,"high":3,"error":4}[.] // 0;
      (if type == "array" then . else .findings end)
      | sort_by(-(.severity | rank)) | .[:10][]
      | "- **\(.severity)** `\(.id)` \(.subject): \(.message | gsub("[\\r\\n]+"; " ") | .[:160])"' "$json"
    jq -e '(if type == "array" then . else .findings end) | length == 0' "$json" >/dev/null && echo "- none"
  else
    echo "The scan produced no report (exit $status); see the step log."
  fi
  echo
  if [ "$status" -eq 0 ]; then
    echo "Gate (\`fail-on: $fail_on\`): passed."
  else
    echo "Gate (\`fail-on: $fail_on\`): failed with exit $status."
  fi
}

main() {
  [ -n "${AD_PATH:-}" ] || die "the 'path' input is required"
  command -v jq >/dev/null || die "jq is required (preinstalled on GitHub-hosted runners)"
  local out=${AD_OUT:-${RUNNER_TEMP:-.}/android-doctor-action} bin command=${AD_COMMAND:-doctor scan}
  local fail_on=${AD_FAIL_ON:-error} baseline=${AD_BASELINE:-}
  mkdir -p "$out"
  rank "$fail_on" >/dev/null || die "fail-on must be one of error, high, medium, warn, none (got '$fail_on')"
  case $command in "doctor scan" | audit) ;; *) die "command must be 'doctor scan' or 'audit' (got '$command')" ;; esac

  if [ -n "${AD_BINARY:-}" ]; then
    [ -x "$AD_BINARY" ] || die "binary '$AD_BINARY' is not an executable file"
    bin=$AD_BINARY
  else
    bin=$(install_release "$out/bin") || exit $?
  fi
  "$bin" --version >&2 || die "cannot run $bin"

  local cmd paths extra bl=()
  read -ra cmd <<< "$command"
  read -ra paths <<< "$AD_PATH"
  read -ra extra <<< "${AD_ARGS:-}"
  [ -n "$baseline" ] && bl=(--baseline "$baseline")
  local sarif="$out/android-doctor.sarif" json="$out/android-doctor.json" err="$out/stderr.txt" rc
  rm -f "$sarif" "$json"
  # --json and --sarif come last so user args cannot redirect them.
  "$bin" --no-color "${cmd[@]}" ${extra[@]+"${extra[@]}"} "${paths[@]}" ${bl[@]+"${bl[@]}"} --sarif "$sarif" --json > "$json" 2> "$err"
  rc=$?
  cat "$err" >&2

  local status note score=""
  status=$(gate_status "$rc" "$json" "$fail_on" "$baseline") || exit 2
  note=$(grep '^baseline ' "$err" | tail -n 1 || true)
  if [ -f "$sarif" ]; then score=$(jq -r '.runs[0].properties.score.value // empty' "$sarif" 2>/dev/null || true); fi

  summary "$json" "$sarif" "$note" "$status" "$fail_on" > "$out/summary.md"
  cat "$out/summary.md"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$out/summary.md" >> "$GITHUB_STEP_SUMMARY"; fi
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "score=$score"
      echo "status=$status"
      if [ -f "$sarif" ]; then echo "sarif=$sarif"; fi
    } >> "$GITHUB_OUTPUT"
  fi
  exit "$status"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
