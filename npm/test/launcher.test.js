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
    env: { PATH: pathDir, ANDROID_DOCTOR_NO_DOWNLOAD: "1" },
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

const { targetFor, assetUrl, ensureBinary } = require("../bin/android-doctor.js");

test("maps platforms to the release asset names", () => {
  assert.strictEqual(targetFor("darwin", "arm64"), "aarch64-apple-darwin");
  assert.strictEqual(targetFor("darwin", "x64"), "x86_64-apple-darwin");
  assert.strictEqual(targetFor("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.strictEqual(targetFor("win32", "x64"), null);
  assert.strictEqual(
    assetUrl("0.1.0", "aarch64-apple-darwin"),
    "https://github.com/doctor-labs/android-doctor/releases/download/v0.1.0/android-doctor-aarch64-apple-darwin.tar.gz",
  );
});

test("downloads, extracts and caches the binary (injected downloader)", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ad-cache-"));
  const src = fs.mkdtempSync(path.join(os.tmpdir(), "ad-src-"));
  fs.writeFileSync(path.join(src, "android-doctor"), "#!/bin/sh\necho ok\n");
  const urls = [];
  const fetchFile = async (url, dest) => {
    urls.push(url);
    const t = spawnSync("tar", ["czf", dest, "-C", src, "android-doctor"]);
    assert.strictEqual(t.status, 0);
  };
  const bin = await ensureBinary({ version: "9.9.9", target: "x86_64-unknown-linux-gnu", dir, fetchFile });
  assert.strictEqual(bin, path.join(dir, "android-doctor"));
  assert.strictEqual(spawnSync(bin, []).status, 0);
  await ensureBinary({ version: "9.9.9", target: "x86_64-unknown-linux-gnu", dir, fetchFile });
  assert.strictEqual(urls.length, 1, "second call uses the cache");
});
