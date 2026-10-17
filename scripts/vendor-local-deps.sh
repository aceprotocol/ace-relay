#!/usr/bin/env bash
# Make the package installable inside `docker build`, where the sibling checkouts
# behind `file:../sdk-ts` does not exist. Ported from ace-mcp's script (sdk-ts only).
#
#   - `npm pack`s ../sdk-ts (a runtime dependency) into vendor/*.tgz and points
#     `@ace-protocol/sdk` at the tarball;
#   - pins the SDK's transitive runtime deps (@noble/* — every
#     non-dev `node_modules/…` entry of sdk-ts's package-lock.json) with exact-version
#     `overrides` in the target package.json, so the image gets the versions the SDK
#     was tested with instead of whatever the registry resolves at build time. (npm
#     does not honour a shrinkwrap inside a `file:` tarball here, so overrides it is.)
#   - refreshes package-lock.json to match (no install, no scripts), then asserts, as a
#     backstop, that every lock entry of those packages has the same version +
#     integrity as in sdk-ts's package-lock.json (exit 1 otherwise).
#
# It REWRITES package.json and package-lock.json in the target directory. Run it
# in CI on a fresh checkout, or locally on a scratch copy:
#   scripts/vendor-local-deps.sh [target-dir]      # default: the repo root
# Undo locally with: git checkout package.json package-lock.json && rm -rf vendor
#
# Prerequisite: ../sdk-ts is built (`npm ci && npm run build` there); its
# package.json ships only dist/, and it has no prepare script.
# Goes away at the formal release, when @ace-protocol/sdk is on npm.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="$(cd "${1:-$repo_root}" && pwd)"
sdk_dir="${SDK_TS_DIR:-$repo_root/../sdk-ts}"

[ -f "$target/package.json" ] || { echo "vendor-local-deps: no package.json in $target" >&2; exit 1; }
[ -d "$sdk_dir" ] || { echo "vendor-local-deps: sdk-ts not found at $sdk_dir (set SDK_TS_DIR)" >&2; exit 1; }
sdk_dir="$(cd "$sdk_dir" && pwd)"
[ -f "$sdk_dir/dist/index.js" ] || { echo "vendor-local-deps: $sdk_dir is not built (run npm ci && npm run build there)" >&2; exit 1; }

[ -f "$sdk_dir/package-lock.json" ] || { echo "vendor-local-deps: $sdk_dir has no package-lock.json" >&2; exit 1; }

mkdir -p "$target/vendor"
rm -f "$target"/vendor/ace-protocol-sdk-*.tgz

tarball="$(cd "$sdk_dir" && npm pack --silent --ignore-scripts --pack-destination "$target/vendor" | tail -n 1)"
echo "vendor-local-deps: packed $tarball"

# One pass over the SDK lock feeds both the overrides and the backstop.
SDK_LOCK="$sdk_dir/package-lock.json" TARGET="$target" TARBALL="$tarball" node --input-type=module -e '
  import { readFileSync, writeFileSync } from "node:fs";
  import { execFileSync } from "node:child_process";
  import { join } from "node:path";
  const { SDK_LOCK, TARGET, TARBALL } = process.env;
  const readJson = (f) => JSON.parse(readFileSync(f, "utf8"));
  const nameOf = (k) => k.slice(k.lastIndexOf("node_modules/") + "node_modules/".length);

  // The SDK runtime deps: every non-dev, non-link package entry (any nesting depth).
  const sdk = new Map();
  for (const [k, v] of Object.entries(readJson(SDK_LOCK).packages)) {
    if (!k.includes("node_modules/") || v.dev || v.link) continue;
    const name = nameOf(k);
    const had = sdk.get(name);
    if (had && had.version !== v.version) throw new Error(`sdk-ts lock holds two versions of ${name} (${had.version}, ${v.version}); cannot pin with one override`);
    sdk.set(name, v);
  }
  if (sdk.size === 0) throw new Error("no runtime dependencies in the sdk-ts lock");

  const pkgFile = join(TARGET, "package.json");
  const pkg = readJson(pkgFile);
  if (!pkg.dependencies?.["@ace-protocol/sdk"]) throw new Error("@ace-protocol/sdk is not a dependency");
  pkg.dependencies["@ace-protocol/sdk"] = `file:vendor/${TARBALL}`;
  for (const name of sdk.keys()) {
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      if (pkg[field]?.[name] !== undefined) throw new Error(`${name} is also a direct ${field} entry; an override would conflict with it`);
    }
  }
  const pins = Object.fromEntries([...sdk].map(([n, v]) => [n, v.version]));
  pkg.overrides = { ...(pkg.overrides ?? {}), ...pins };
  writeFileSync(pkgFile, JSON.stringify(pkg, null, 2) + "\n");
  console.log("vendor-local-deps: overrides " + Object.entries(pins).map(([n, v]) => `${n}@${v}`).join(", "));

  execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: TARGET, stdio: "inherit" });

  // Backstop: every lock entry of the pinned packages must equal its sdk-ts lock entry.
  const app = Object.entries(readJson(join(TARGET, "package-lock.json")).packages).filter(([k]) => k.includes("node_modules/"));
  const bad = []; let seen = 0;
  for (const [k, v] of app) {
    const want = sdk.get(nameOf(k));
    if (!want) continue;
    seen++;
    if (want.version !== v.version || want.integrity !== v.integrity) bad.push(`${k}: ${v.version} ${v.integrity} != sdk-ts ${want.version} ${want.integrity}`);
  }
  for (const name of sdk.keys()) if (!app.some(([k]) => nameOf(k) === name)) bad.push(`${name}: missing from the rewritten lock`);
  if (bad.length) { console.error("vendor-local-deps: SDK transitive deps drifted from sdk-ts/package-lock.json:\n  " + bad.join("\n  ")); process.exit(1); }
  console.log(`vendor-local-deps: ${seen} lock entries of ${sdk.size} SDK runtime deps match sdk-ts/package-lock.json`);
'
echo "vendor-local-deps: @ace-protocol/sdk -> file:vendor/$tarball (transitive deps pinned by overrides)"
