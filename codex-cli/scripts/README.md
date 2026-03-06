# npm releases

Use the staging helper in the repo root to generate npm tarballs for a release. For
example, to stage the CLI, responses proxy, and SDK packages for version `0.6.0`:

```bash
./scripts/stage_npm_packages.py \
  --release-version 0.6.0 \
  --package codex \
  --package codex-responses-api-proxy \
  --package codex-sdk
```

This downloads the required native package archive artifacts, hydrates `vendor/` for
each package, and writes tarballs to `dist/npm/`.

When `--package codex` is provided, the staging helper builds the lightweight
Codex meta package plus all platform-native variants that are later published
under platform-specific dist-tags. By default it stages `@openai/codex`, but
you can override that for a fork:

```bash
./scripts/stage_npm_packages.py \
  --release-version 0.6.0 \
  --package codex \
  --npm-package-name @eyycheev/codex
```

That produces tarballs whose package metadata, platform alias names, and copied
README install snippets all point at `@eyycheev/codex` while still reusing the
same native release artifacts.

Direct `build_npm_package.py` invocations are still useful for package-specific
debugging, but native packages expect `--vendor-src` to point at a prehydrated
`vendor/` tree. Release packaging should use `scripts/stage_npm_packages.py`.

If you need to invoke `build_npm_package.py` directly, run
`codex-cli/scripts/install_native_deps.py --component codex-package` first and pass
`--vendor-src` pointing to the directory that contains the populated `vendor/` tree.
The direct builder also accepts `--npm-package-name`.

If you only support a subset of platform packages for a fork, pass
`--platform-package` one or more times when staging the meta package:

```bash
python3 codex-cli/scripts/build_npm_package.py \
  --package codex \
  --release-version 0.6.0 \
  --npm-package-name @eyycheev/codex \
  --platform-package codex-darwin-arm64 \
  --platform-package codex-linux-x64-gnu \
  --staging-dir /tmp/codex-npm-stage
```

To publish staged tarballs from a directory, use the repo helper:

```bash
python3 scripts/publish_npm_packages.py \
  --dir dist/npm \
  --version 0.6.0
```
