#!/usr/bin/env node
// `npx android-doctor ...` runs the native android-doctor binary found on PATH and
// forwards its exit code. No dependencies. The binary is not bundled: install it first.
"use strict";

const { spawnSync } = require("node:child_process");

const result = spawnSync("android-doctor", process.argv.slice(2), { stdio: "inherit" });

if (result.error && result.error.code === "ENOENT") {
  console.error(
    "android-doctor: native binary not found on PATH. Install a release binary from\n" +
      "https://github.com/Vaibhav91one/android-doctor/releases or run:\n" +
      "  cargo install --git https://github.com/Vaibhav91one/android-doctor android-doctor",
  );
  process.exit(127);
}
if (result.error) {
  console.error(`android-doctor: could not run the binary: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
