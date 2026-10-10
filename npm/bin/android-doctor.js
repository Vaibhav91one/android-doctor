#!/usr/bin/env node
// `npx android-doctor ...` runs the native android-doctor binary. On first run it downloads the
// release binary for this platform (android-doctor-<target>.tar.gz from the GitHub release that
// matches this package's version) into a cache dir; failing that it uses a binary on PATH.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO = "doctor-labs/android-doctor";
const TARGETS = {
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-gnu",
};

function targetFor(platform, arch) {
  return TARGETS[`${platform}-${arch}`] || null;
}

function assetUrl(version, target) {
  return `https://github.com/${REPO}/releases/download/v${version}/android-doctor-${target}.tar.gz`;
}

function cacheDir(version, env = process.env) {
  const base = env.ANDROID_DOCTOR_CACHE || env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
  return path.join(base, "android-doctor", version);
}

async function download(url, dest) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
}

// Returns the path to a verified cached binary, downloading it first when missing.
async function ensureBinary({ version, target, dir, fetchFile = download, spawn = spawnSync }) {
  const bin = path.join(dir, "android-doctor");
  const works = () => fs.existsSync(bin) && spawn(bin, ["--version"], { stdio: "ignore" }).status === 0;
  if (works()) return bin;
  fs.mkdirSync(dir, { recursive: true });
  const tgz = path.join(dir, "android-doctor.tar.gz");
  await fetchFile(assetUrl(version, target), tgz);
  const x = spawn("tar", ["xzf", tgz, "-C", dir], { stdio: "ignore" });
  fs.rmSync(tgz, { force: true });
  if (x.status !== 0) throw new Error("could not extract the downloaded archive");
  fs.chmodSync(bin, 0o755);
  if (!works()) throw new Error("the downloaded binary does not run on this machine");
  return bin;
}

function run(bin) {
  const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
  if (result.error && result.error.code === "ENOENT") return null;
  if (result.error) {
    console.error(`android-doctor: could not run the binary: ${result.error.message}`);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

async function main() {
  const target = targetFor(process.platform, process.arch);
  let note = `unsupported platform ${process.platform}-${process.arch} (release binaries: ${Object.keys(TARGETS).join(", ")})`;
  if (process.env.ANDROID_DOCTOR_NO_DOWNLOAD) {
    note = "download disabled by ANDROID_DOCTOR_NO_DOWNLOAD";
  } else if (target) {
    const version = require("../package.json").version;
    try {
      const bin = await ensureBinary({ version, target, dir: cacheDir(version) });
      run(bin);
    } catch (e) {
      note = `download failed: ${e.message}`;
    }
  }
  run("android-doctor"); // fall back to a binary on PATH
  console.error(
    `android-doctor: no native binary available (${note}).\n` +
      `Install one from https://github.com/${REPO}/releases or run:\n` +
      "  cargo install android-doctor",
  );
  process.exit(127);
}

if (require.main === module) main();
module.exports = { targetFor, assetUrl, cacheDir, ensureBinary };
