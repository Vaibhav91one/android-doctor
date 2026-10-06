// The launcher forwards args and the exit code of the native binary, and exits 127 when absent.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const LAUNCHER = path.join(__dirname, "..", "bin", "android-doctor.js");

function run(pathDir, args) {
  return spawnSync(process.execPath, [LAUNCHER, ...args], {
    env: { PATH: pathDir },
    encoding: "utf8",
  });
}

test("forwards arguments and exit code to the binary on PATH", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ad-npm-"));
  const bin = path.join(dir, "android-doctor");
  fs.writeFileSync(bin, '#!/bin/sh\necho "args:$*"\nexit 3\n', { mode: 0o755 });
  const r = run(dir, ["identify", "x.img"]);
  assert.strictEqual(r.status, 3);
  assert.match(r.stdout, /args:identify x\.img/);
});

test("exits 127 with an install hint when the binary is missing", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ad-npm-"));
  const r = run(dir, ["--version"]);
  assert.strictEqual(r.status, 127);
  assert.match(r.stderr, /releases/);
});
