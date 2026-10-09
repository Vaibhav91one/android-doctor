# doctor/1 output contract

Shared machine-output contract for the doctor tools: luasec, pcap-doctor, android-doctor,
sim-doctor, ble-doctor. This file is identical in every repo (`docs/doctor-contract.md`).
Change it in all five repos at once or not at all.

## Scope

Applies to every command that produces **findings** (luasec scan, `pcap-doctor analyze`,
`android-doctor audit` / `doctor scan`, `sim-doctor scan`, `ble-doctor scan` / `analyze`).
Other commands (identify, extract, rules list, lpa-style commands, ...) may keep their own JSON.

## 1. Envelope (`--json`)

One JSON object on stdout. Key order is not significant. No timestamps or other run-varying
values outside `data`, so two runs over the same input give the same top level and findings.

```json
{
  "schema": "doctor/1",
  "tool": "pcap-doctor",
  "version": "0.8.0",
  "exit_code": 1,
  "score": { "value": 72, "label": "needs work", "model": "pcap/1", "coverage_gaps": 0 },
  "findings": [ { "...": "see 2" } ],
  "data": { }
}
```

| Key | Type | Rule |
|---|---|---|
| `schema` | string | Exactly `"doctor/1"`. |
| `tool` | string | The binary name users run. |
| `version` | string | The tool's own version (semver). |
| `exit_code` | int | The process exit code this run returns (section 4). |
| `score` | object | Section 3. |
| `findings` | array | Section 2. Only failed checks / real findings. Passed checks go under `data`. Sorted by severity (critical first), then `id`, then `fingerprint`. |
| `data` | object | Tool-specific detail (old envelope content, stats, passed checks, coverage...). Free shape. May be `{}`. |

When `--baseline` is given, add top-level `"baseline": {"new": N, "unchanged": N, "fixed": N}`
and set `baseline_state` on every finding.

## 2. Finding

| Key | Type | Required | Rule |
|---|---|---|---|
| `id` | string | yes | Rule id, stable across versions (e.g. `tls/weak-cipher`, `LUA-101`). |
| `fingerprint` | string | yes | Stable identity of *this* finding for baselines: lowercase hex, 16 chars, hashed from rule id + location identity, excluding volatile parts (line numbers that shift, ephemeral ports, counts). Same value as SARIF `partialFingerprints["doctorFinding/v1"]`. |
| `severity` | string | yes | One of `critical`, `high`, `medium`, `low`, `info`. |
| `confidence` | string | no | One of `certain`, `high`, `medium`, `low`. Omit when the tool has no notion of it. |
| `category` | string | yes | Short lowercase grouping (`crypto`, `auth`, `exposure`, ...). |
| `message` | string | yes | One-line human statement of the problem. |
| `location` | object | yes | `{"kind": K, "ref": "..."}` plus optional `line`, `column` (ints). `kind` is one of `file`, `flow`, `frame`, `image`, `card-path`, `device`, `service`, `none`. |
| `evidence` | array | no | `[{"ref": "...", "value": "..."}]`, e.g. a frame number, a snippet, an APDU. |
| `remedy` | string or null | yes | How to fix it; `null` when there is no known fix. |
| `baseline_state` | string | only with `--baseline` | `new` or `unchanged`. |

Tools may add extra keys to a finding; consumers must ignore unknown keys.

Severity mapping from older vocabularies: `error` -> `critical`, `warn` -> `low`.

## 3. Score

`{"value": int 0-100, "label": L, "model": "<tool>/<n>", "coverage_gaps": int}`

- Each tool keeps its own formula. `model` names it and changes (`/2`) whenever the formula changes.
- `label`: `good` (>= 90), `needs work` (>= 60), `critical` (< 60). `incomplete` replaces `good`
  when `coverage_gaps > 0`.
- The formula is documented in the tool's README next to the model name.

## 4. Exit codes

| Code | Meaning |
|---|---|
| 0 | Ran; no finding at or above `--fail-on`. |
| 1 | Ran; at least one finding at or above `--fail-on`. |
| 2 | Usage error, bad input, or the tool could not run. |
| 3 | `--baseline` given; at least one **new** finding at or above `--fail-on`. Takes precedence over 1. |
| 130 | Interrupted (SIGINT). |

- Every findings command accepts `--fail-on {critical,high,medium,low,info}`. Each tool keeps its
  current default threshold and documents it.
- Under `--baseline`, only new findings count for the gate: 3 if any new finding meets the
  threshold, else 0.
- The exit code also appears as `exit_code` in the envelope.

## 5. SARIF

`--sarif FILE` writes SARIF 2.1.0. Each result carries
`partialFingerprints: {"doctorFinding/v1": <fingerprint>}` and the run carries
`properties.score` (section 3 object). Level mapping: critical/high -> `error`,
medium -> `warning`, low/info -> `note`.

## 6. Baseline

`--baseline FILE` accepts a previous `--json` envelope (doctor/1) and matches findings by
`fingerprint` only. Coverage gaps are never suppressed by a baseline.

## 7. MCP

`<tool> mcp` serves MCP over stdio. Each findings tool:

- runs the CLI's own code path with `--json` and returns the envelope **unchanged** (byte-identical
  to the CLI for the same arguments);
- accepts the CLI's flags as arguments, including `baseline`, `fail_on`, `sarif`; flags that make no
  sense over MCP (`tui`, `help`, `version`, interactive prompts) may be excluded, and the exclusions
  are listed in the README.

## 8. Sanitization

Strings derived from the analysed target (file content, packet fields, card data, device names)
are untrusted. Every renderer that writes to a **terminal, Markdown, HTML or an LLM prompt** must
strip or escape: C0/C1 control characters (including ESC), bidi controls (U+202A-U+202E,
U+2066-U+2069), zero-width characters (U+200B-U+200D, U+FEFF) and line/paragraph separators
(U+2028, U+2029). JSON and SARIF rely on the serializer's escaping and keep values as-is.
Each tool has one shared helper for this and a test that feeds an ESC sequence through the
human renderer and asserts it does not reach the output.

## 9. Conformance test

Each repo has one test that runs a findings command with `--json` over a fixture and asserts:
the top-level keys and `schema == "doctor/1"`; every finding's required keys and enum values;
`exit_code` equals the real exit code; `fingerprint` is 16 lowercase hex; the same run twice gives
identical output apart from `data` (which may hold timestamps).
