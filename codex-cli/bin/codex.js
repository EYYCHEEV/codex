#!/usr/bin/env node
// Unified entry point for the Codex CLI.

import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "fs";
import { createRequire } from "node:module";
import path from "path";
import { fileURLToPath } from "url";

// __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);
const codexPackageName =
  require(path.join(__dirname, "..", "package.json")).name || "@openai/codex";

function deriveSiblingPackageName(packageName, suffix) {
  if (packageName.startsWith("@")) {
    const [scope, baseName] = packageName.split("/");
    if (scope && baseName) {
      return `${scope}/${baseName}-${suffix}`;
    }
  }

  return `${packageName}-${suffix}`;
}

const TARGET_CANDIDATES_BY_PLATFORM = {
  "linux:x64": [
    {
      packageName: deriveSiblingPackageName(codexPackageName, "linux-x64"),
      targetTriple: "x86_64-unknown-linux-musl",
    },
    {
      packageName: deriveSiblingPackageName(codexPackageName, "linux-x64-gnu"),
      targetTriple: "x86_64-unknown-linux-gnu",
    },
  ],
  "linux:arm64": [
    {
      packageName: deriveSiblingPackageName(codexPackageName, "linux-arm64"),
      targetTriple: "aarch64-unknown-linux-musl",
    },
  ],
  "darwin:x64": [
    {
      packageName: deriveSiblingPackageName(codexPackageName, "darwin-x64"),
      targetTriple: "x86_64-apple-darwin",
    },
  ],
  "darwin:arm64": [
    {
      packageName: deriveSiblingPackageName(codexPackageName, "darwin-arm64"),
      targetTriple: "aarch64-apple-darwin",
    },
  ],
  "win32:x64": [
    {
      packageName: deriveSiblingPackageName(codexPackageName, "win32-x64"),
      targetTriple: "x86_64-pc-windows-msvc",
    },
  ],
  "win32:arm64": [
    {
      packageName: deriveSiblingPackageName(codexPackageName, "win32-arm64"),
      targetTriple: "aarch64-pc-windows-msvc",
    },
  ],
};

const { platform, arch } = process;
const platformKey = `${platform === "android" ? "linux" : platform}:${arch}`;
const targetCandidates = TARGET_CANDIDATES_BY_PLATFORM[platformKey];

if (!targetCandidates) {
  throw new Error(`Unsupported platform: ${platform} (${arch})`);
}

const codexBinaryName = process.platform === "win32" ? "codex.exe" : "codex";
const localVendorRoot = path.join(__dirname, "..", "vendor");

let selectedCandidate = null;
let vendorRoot = null;

for (const candidate of targetCandidates) {
  try {
    const packageJsonPath = require.resolve(`${candidate.packageName}/package.json`);
    selectedCandidate = candidate;
    vendorRoot = path.join(path.dirname(packageJsonPath), "vendor");
    break;
  } catch {
    const localBinaryPath = path.join(
      localVendorRoot,
      candidate.targetTriple,
      "codex",
      codexBinaryName,
    );
    if (existsSync(localBinaryPath)) {
      selectedCandidate = candidate;
      vendorRoot = localVendorRoot;
      break;
    }
  }
}

if (!selectedCandidate || !vendorRoot) {
  const packageManager = detectPackageManager();
  const updateCommand =
    packageManager === "bun"
      ? `bun install -g ${codexPackageName}@latest`
      : `npm install -g ${codexPackageName}@latest`;
  const missingPackages = targetCandidates.map(({ packageName }) => packageName).join(", ");
  throw new Error(
    `Missing optional dependency for ${platform}/${arch} (${missingPackages}). Reinstall Codex: ${updateCommand}`,
  );
}

const { packageName: platformPackage, targetTriple } = selectedCandidate;
const archRoot = path.join(vendorRoot, targetTriple);
const binaryPath = path.join(archRoot, "codex", codexBinaryName);

// Use an asynchronous spawn instead of spawnSync so that Node is able to
// respond to signals (e.g. Ctrl-C / SIGINT) while the native binary is
// executing. This allows us to forward those signals to the child process
// and guarantees that when either the child terminates or the parent
// receives a fatal signal, both processes exit in a predictable manner.

function getUpdatedPath(newDirs) {
  const pathSep = process.platform === "win32" ? ";" : ":";
  const existingPath = process.env.PATH || "";
  const updatedPath = [
    ...newDirs,
    ...existingPath.split(pathSep).filter(Boolean),
  ].join(pathSep);
  return updatedPath;
}

/**
 * Use heuristics to detect the package manager that was used to install Codex
 * in order to give the user a hint about how to update it.
 */
function detectPackageManager() {
  const userAgent = process.env.npm_config_user_agent || "";
  if (/\bbun\//.test(userAgent)) {
    return "bun";
  }

  const execPath = process.env.npm_execpath || "";
  if (execPath.includes("bun")) {
    return "bun";
  }

  if (
    __dirname.includes(".bun/install/global") ||
    __dirname.includes(".bun\\install\\global")
  ) {
    return "bun";
  }

  return userAgent ? "npm" : null;
}

const additionalDirs = [];
const pathDir = path.join(archRoot, "path");
if (existsSync(pathDir)) {
  additionalDirs.push(pathDir);
}
const updatedPath = getUpdatedPath(additionalDirs);

const env = { ...process.env, PATH: updatedPath };
const packageManagerEnvVar =
  detectPackageManager() === "bun"
    ? "CODEX_MANAGED_BY_BUN"
    : "CODEX_MANAGED_BY_NPM";
env[packageManagerEnvVar] = "1";
env.CODEX_MANAGED_PACKAGE_ROOT = realpathSync(path.join(__dirname, ".."));

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env,
});

child.on("error", (err) => {
  // Typically triggered when the binary is missing or not executable.
  // Re-throwing here will terminate the parent with a non-zero exit code
  // while still printing a helpful stack trace.
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

// Forward common termination signals to the child so that it shuts down
// gracefully. In the handler we temporarily disable the default behavior of
// exiting immediately; once the child has been signaled we simply wait for
// its exit event which will in turn terminate the parent (see below).
const forwardSignal = (signal) => {
  if (child.killed) {
    return;
  }
  try {
    child.kill(signal);
  } catch {
    /* ignore */
  }
};

["SIGINT", "SIGTERM", "SIGHUP"].forEach((sig) => {
  process.on(sig, () => forwardSignal(sig));
});

// When the child exits, mirror its termination reason in the parent so that
// shell scripts and other tooling observe the correct exit status.
// Wrap the lifetime of the child process in a Promise so that we can await
// its termination in a structured way. The Promise resolves with an object
// describing how the child exited: either via exit code or due to a signal.
const childResult = await new Promise((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve({ type: "signal", signal });
    } else {
      resolve({ type: "code", exitCode: code ?? 1 });
    }
  });
});

if (childResult.type === "signal") {
  // Re-emit the same signal so that the parent terminates with the expected
  // semantics (this also sets the correct exit code of 128 + n).
  process.kill(process.pid, childResult.signal);
} else {
  process.exit(childResult.exitCode);
}
