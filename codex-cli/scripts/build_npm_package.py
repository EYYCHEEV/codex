#!/usr/bin/env python3
"""Stage and optionally package the Codex npm module."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CODEX_CLI_ROOT = SCRIPT_DIR.parent
REPO_ROOT = CODEX_CLI_ROOT.parent
RESPONSES_API_PROXY_NPM_ROOT = REPO_ROOT / "codex-rs" / "responses-api-proxy" / "npm"
CODEX_SDK_ROOT = REPO_ROOT / "sdk" / "typescript"
CODEX_NPM_NAME = "@openai/codex"
CODEX_PACKAGE_COMPONENT = "codex-package"
CODEX_PACKAGE_ENTRIES = ("codex-package.json", "bin", "codex-resources", "codex-path")
DEFAULT_GITHUB_REPO_URL = "git+https://github.com/openai/codex.git"

# Platform package keys stay stable inside the staging scripts; the actual npm
# alias names are derived from the configured Codex package name at stage time.
CODEX_PLATFORM_PACKAGES: dict[str, dict[str, str]] = {
    "codex-linux-x64": {
        "npm_tag": "linux-x64",
        "target_triple": "x86_64-unknown-linux-musl",
        "os": "linux",
        "cpu": "x64",
    },
    "codex-linux-x64-gnu": {
        "npm_tag": "linux-x64-gnu",
        "target_triple": "x86_64-unknown-linux-gnu",
        "os": "linux",
        "cpu": "x64",
    },
    "codex-linux-arm64": {
        "npm_tag": "linux-arm64",
        "target_triple": "aarch64-unknown-linux-musl",
        "os": "linux",
        "cpu": "arm64",
    },
    "codex-darwin-x64": {
        "npm_tag": "darwin-x64",
        "target_triple": "x86_64-apple-darwin",
        "os": "darwin",
        "cpu": "x64",
    },
    "codex-darwin-arm64": {
        "npm_tag": "darwin-arm64",
        "target_triple": "aarch64-apple-darwin",
        "os": "darwin",
        "cpu": "arm64",
    },
    "codex-win32-x64": {
        "npm_tag": "win32-x64",
        "target_triple": "x86_64-pc-windows-msvc",
        "os": "win32",
        "cpu": "x64",
    },
    "codex-win32-arm64": {
        "npm_tag": "win32-arm64",
        "target_triple": "aarch64-pc-windows-msvc",
        "os": "win32",
        "cpu": "arm64",
    },
}

PACKAGE_EXPANSIONS: dict[str, list[str]] = {
    "codex": [
        "codex",
        "codex-linux-x64",
        "codex-linux-arm64",
        "codex-darwin-x64",
        "codex-darwin-arm64",
        "codex-win32-x64",
        "codex-win32-arm64",
    ],
}

PACKAGE_NATIVE_COMPONENTS: dict[str, list[str]] = {
    "codex": [],
    "codex-linux-x64": [CODEX_PACKAGE_COMPONENT],
    "codex-linux-x64-gnu": ["bwrap", "codex", "rg"],
    "codex-linux-arm64": [CODEX_PACKAGE_COMPONENT],
    "codex-darwin-x64": [CODEX_PACKAGE_COMPONENT],
    "codex-darwin-arm64": [CODEX_PACKAGE_COMPONENT],
    "codex-win32-x64": [CODEX_PACKAGE_COMPONENT],
    "codex-win32-arm64": [CODEX_PACKAGE_COMPONENT],
    "codex-responses-api-proxy": ["codex-responses-api-proxy"],
    "codex-sdk": [],
}

PACKAGE_TARGET_FILTERS: dict[str, str] = {
    package_name: package_config["target_triple"]
    for package_name, package_config in CODEX_PLATFORM_PACKAGES.items()
}

PACKAGE_CHOICES = tuple(PACKAGE_NATIVE_COMPONENTS)
PLATFORM_PACKAGE_CHOICES = tuple(CODEX_PLATFORM_PACKAGES)

COMPONENT_DEST_DIR: dict[str, str] = {
    "bwrap": "codex-resources",
    "codex": "codex",
    "codex-responses-api-proxy": "codex-responses-api-proxy",
    "codex-windows-sandbox-setup": "codex",
    "codex-command-runner": "codex",
    "rg": "path",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build or stage the Codex CLI npm package.")
    parser.add_argument(
        "--package",
        choices=PACKAGE_CHOICES,
        default="codex",
        help="Which npm package to stage (default: codex).",
    )
    parser.add_argument(
        "--version",
        help="Version number to write to package.json inside the staged package.",
    )
    parser.add_argument(
        "--release-version",
        help=(
            "Version to stage for npm release."
        ),
    )
    parser.add_argument(
        "--staging-dir",
        type=Path,
        help=(
            "Directory to stage the package contents. Defaults to a new temporary directory "
            "if omitted. The directory must be empty when provided."
        ),
    )
    parser.add_argument(
        "--tmp",
        dest="staging_dir",
        type=Path,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--pack-output",
        type=Path,
        help="Path where the generated npm tarball should be written.",
    )
    parser.add_argument(
        "--npm-package-name",
        default=None,
        help=(
            "Override the published Codex npm package name (default: package.json name or "
            "the CODEX_NPM_PACKAGE_NAME environment variable)."
        ),
    )
    parser.add_argument(
        "--platform-package",
        dest="platform_packages",
        action="append",
        choices=PLATFORM_PACKAGE_CHOICES,
        help=(
            "Limit the Codex meta package to the specified platform package keys. "
            "Only applies when --package codex is used."
        ),
    )
    parser.add_argument(
        "--vendor-src",
        type=Path,
        help="Directory containing pre-installed native binaries to bundle (vendor root).",
    )
    parser.add_argument(
        "--allow-missing-native-component",
        dest="allow_missing_native_components",
        action="append",
        default=[],
        help=(
            "Native component that may be absent from --vendor-src. Intended for CI "
            "compatibility with older artifact workflows; releases should not use this."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    package = args.package
    version = args.version
    release_version = args.release_version
    if release_version:
        if version and version != release_version:
            raise RuntimeError("--version and --release-version must match when both are provided.")
        version = release_version

    if not version:
        raise RuntimeError("Must specify --version or --release-version.")

    if args.platform_packages and package != "codex":
        raise RuntimeError("--platform-package may only be used with --package codex.")

    package_names = derive_package_names(resolve_codex_npm_name(args.npm_package_name))
    selected_platform_packages = args.platform_packages or PACKAGE_EXPANSIONS["codex"][1:]
    staging_dir, created_temp = prepare_staging_dir(args.staging_dir)

    try:
        stage_sources(
            staging_dir,
            version,
            package,
            package_names,
            selected_platform_packages=selected_platform_packages,
        )

        vendor_src = args.vendor_src.resolve() if args.vendor_src else None
        native_components = PACKAGE_NATIVE_COMPONENTS.get(package, [])
        target_filter = PACKAGE_TARGET_FILTERS.get(package)

        if native_components:
            if vendor_src is None:
                components_str = ", ".join(native_components)
                raise RuntimeError(
                    "Native components "
                    f"({components_str}) required for package '{package}'. Provide --vendor-src "
                    "pointing to a directory containing pre-installed binaries."
                )

            copy_native_binaries(
                vendor_src,
                staging_dir,
                native_components,
                target_filter={target_filter} if target_filter else None,
                allow_missing_components=set(args.allow_missing_native_components),
            )

        if release_version:
            staging_dir_str = str(staging_dir)
            if package == "codex":
                print(
                    f"Staged version {version} for release in {staging_dir_str}\n\n"
                    "Verify the CLI:\n"
                    f"    node {staging_dir_str}/bin/codex.js --version\n"
                    f"    node {staging_dir_str}/bin/codex.js --help\n\n"
                )
            elif package == "codex-responses-api-proxy":
                print(
                    f"Staged version {version} for release in {staging_dir_str}\n\n"
                    "Verify the responses API proxy:\n"
                    f"    node {staging_dir_str}/bin/codex-responses-api-proxy.js --help\n\n"
                )
            elif package in CODEX_PLATFORM_PACKAGES:
                print(
                    f"Staged version {version} for release in {staging_dir_str}\n\n"
                    "Verify native payload contents:\n"
                    f"    ls {staging_dir_str}/vendor\n\n"
                )
            else:
                print(
                    f"Staged version {version} for release in {staging_dir_str}\n\n"
                    "Verify the SDK contents:\n"
                    f"    ls {staging_dir_str}/dist\n"
                    "    node -e \"import('./dist/index.js').then(() => console.log('ok'))\"\n\n"
                )
        else:
            print(f"Staged package in {staging_dir}")

        if args.pack_output is not None:
            output_path = run_npm_pack(staging_dir, args.pack_output)
            print(f"npm pack output written to {output_path}")
    finally:
        if created_temp:
            # Preserve the staging directory for further inspection.
            pass

    return 0


def resolve_codex_npm_name(override: str | None) -> str:
    npm_name = (override or "").strip() or os.environ.get("CODEX_NPM_PACKAGE_NAME", "").strip()
    if npm_name:
        validate_codex_npm_name(npm_name)
        return npm_name

    return CODEX_NPM_NAME


def validate_codex_npm_name(npm_name: str) -> None:
    if npm_name.startswith("@"):
        if npm_name.count("/") != 1:
            raise RuntimeError(
                "Scoped npm package names must look like '@scope/name'. "
                f"Got '{npm_name}'."
            )
        return

    if "/" in npm_name:
        raise RuntimeError(f"Unscoped npm package names cannot contain '/': '{npm_name}'")


def derive_package_names(codex_npm_name: str) -> dict[str, str]:
    return {
        "codex": codex_npm_name,
        "codex-responses-api-proxy": derive_related_package_name(
            codex_npm_name, "responses-api-proxy"
        ),
        "codex-sdk": derive_related_package_name(codex_npm_name, "sdk"),
        **{
            package_name: derive_related_package_name(
                codex_npm_name, package_name.removeprefix("codex-")
            )
            for package_name in CODEX_PLATFORM_PACKAGES
        },
    }


def derive_related_package_name(codex_npm_name: str, suffix: str) -> str:
    if codex_npm_name.startswith("@"):
        scope, base_name = codex_npm_name.split("/", 1)
        return f"{scope}/{base_name}-{suffix}"

    return f"{codex_npm_name}-{suffix}"


def resolve_repository_metadata(directory: str) -> dict[str, str]:
    return {
        "type": "git",
        "url": detect_repository_git_url(),
        "directory": directory,
    }


def detect_repository_git_url() -> str:
    try:
        remote = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=REPO_ROOT,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return DEFAULT_GITHUB_REPO_URL

    if not remote:
        return DEFAULT_GITHUB_REPO_URL

    if remote.startswith("git+https://"):
        return remote

    if remote.startswith("https://github.com/"):
        normalized = remote.removesuffix(".git")
        return f"git+{normalized}.git"

    if remote.startswith("git@github.com:"):
        normalized = remote.removeprefix("git@github.com:").removesuffix(".git")
        return f"git+https://github.com/{normalized}.git"

    return DEFAULT_GITHUB_REPO_URL


def repository_http_url(repository_git_url: str) -> str:
    if repository_git_url.startswith("git+https://"):
        return repository_git_url.removeprefix("git+").removesuffix(".git")
    if repository_git_url.startswith("https://"):
        return repository_git_url.removesuffix(".git")
    return "https://github.com/openai/codex"


def copy_release_readme(
    readme_src: Path,
    readme_dest: Path,
    package_names: dict[str, str],
) -> None:
    repository_git_url = detect_repository_git_url()
    repository_url = repository_http_url(repository_git_url)
    content = readme_src.read_text(encoding="utf-8")
    replacements = [
        ("@openai/codex-responses-api-proxy", package_names["codex-responses-api-proxy"]),
        ("@openai/codex-sdk", package_names["codex-sdk"]),
        ("@openai/codex", package_names["codex"]),
        ("git+https://github.com/openai/codex.git", repository_git_url),
        ("https://github.com/openai/codex", repository_url),
    ]

    for old, new in replacements:
        content = content.replace(old, new)

    readme_dest.write_text(content, encoding="utf-8")


def prepare_staging_dir(staging_dir: Path | None) -> tuple[Path, bool]:
    if staging_dir is not None:
        staging_dir = staging_dir.resolve()
        staging_dir.mkdir(parents=True, exist_ok=True)
        if any(staging_dir.iterdir()):
            raise RuntimeError(f"Staging directory {staging_dir} is not empty.")
        return staging_dir, False

    temp_dir = Path(tempfile.mkdtemp(prefix="codex-npm-stage-"))
    return temp_dir, True


def stage_sources(
    staging_dir: Path,
    version: str,
    package: str,
    package_names: dict[str, str],
    *,
    selected_platform_packages: list[str],
) -> None:
    package_json: dict
    package_json_path: Path | None = None

    if package == "codex":
        bin_dir = staging_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CODEX_CLI_ROOT / "bin" / "codex.js", bin_dir / "codex.js")
        rg_manifest = CODEX_CLI_ROOT / "bin" / "rg"
        if rg_manifest.exists():
            shutil.copy2(rg_manifest, bin_dir / "rg")

        readme_src = REPO_ROOT / "README.md"
        if readme_src.exists():
            copy_release_readme(readme_src, staging_dir / "README.md", package_names)

        package_json_path = CODEX_CLI_ROOT / "package.json"
    elif package in CODEX_PLATFORM_PACKAGES:
        platform_package = CODEX_PLATFORM_PACKAGES[package]
        platform_npm_tag = platform_package["npm_tag"]
        platform_version = compute_platform_package_version(version, platform_npm_tag)

        readme_src = REPO_ROOT / "README.md"
        if readme_src.exists():
            copy_release_readme(readme_src, staging_dir / "README.md", package_names)

        with open(CODEX_CLI_ROOT / "package.json", "r", encoding="utf-8") as fh:
            codex_package_json = json.load(fh)

        package_json = {
            "name": package_names["codex"],
            "version": platform_version,
            "license": codex_package_json.get("license", "Apache-2.0"),
            "os": [platform_package["os"]],
            "cpu": [platform_package["cpu"]],
            "files": ["vendor"],
            "repository": resolve_repository_metadata("codex-cli"),
        }

        engines = codex_package_json.get("engines")
        if isinstance(engines, dict):
            package_json["engines"] = engines

        package_manager = codex_package_json.get("packageManager")
        if isinstance(package_manager, str):
            package_json["packageManager"] = package_manager
    elif package == "codex-responses-api-proxy":
        bin_dir = staging_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        launcher_src = RESPONSES_API_PROXY_NPM_ROOT / "bin" / "codex-responses-api-proxy.js"
        shutil.copy2(launcher_src, bin_dir / "codex-responses-api-proxy.js")

        readme_src = RESPONSES_API_PROXY_NPM_ROOT / "README.md"
        if readme_src.exists():
            copy_release_readme(readme_src, staging_dir / "README.md", package_names)

        package_json_path = RESPONSES_API_PROXY_NPM_ROOT / "package.json"
    elif package == "codex-sdk":
        package_json_path = CODEX_SDK_ROOT / "package.json"
        stage_codex_sdk_sources(staging_dir, package_names)
    else:
        raise RuntimeError(f"Unknown package '{package}'.")

    if package_json_path is not None:
        with open(package_json_path, "r", encoding="utf-8") as fh:
            package_json = json.load(fh)
        package_json["name"] = package_names.get(package, package_json["name"])
        package_json["version"] = version
        repository = package_json.get("repository")
        repository_directory = repository.get("directory") if isinstance(repository, dict) else None
        package_json["repository"] = resolve_repository_metadata(repository_directory or ".")

    if package == "codex":
        package_json["files"] = ["bin/codex.js"]
        package_json["optionalDependencies"] = {
            package_names[platform_package]: (
                f"npm:{package_names['codex']}@"
                f"{compute_platform_package_version(version, CODEX_PLATFORM_PACKAGES[platform_package]['npm_tag'])}"
            )
            for platform_package in selected_platform_packages
        }

    elif package == "codex-sdk":
        scripts = package_json.get("scripts")
        if isinstance(scripts, dict):
            scripts.pop("prepare", None)

        dependencies = package_json.get("dependencies")
        if not isinstance(dependencies, dict):
            dependencies = {}
        dependencies[package_names["codex"]] = version
        package_json["dependencies"] = dependencies

    if str(package_json.get("name", "")).startswith("@"):
        package_json["publishConfig"] = {"access": "public"}

    with open(staging_dir / "package.json", "w", encoding="utf-8") as out:
        json.dump(package_json, out, indent=2)
        out.write("\n")


def compute_platform_package_version(version: str, platform_tag: str) -> str:
    # npm forbids republishing the same package name/version, so each
    # platform-specific tarball needs a unique version string.
    return f"{version}-{platform_tag}"


def run_command(cmd: list[str], cwd: Path | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


def stage_codex_sdk_sources(staging_dir: Path, package_names: dict[str, str]) -> None:
    package_root = CODEX_SDK_ROOT

    run_command(["pnpm", "install", "--frozen-lockfile"], cwd=package_root)
    run_command(["pnpm", "run", "build"], cwd=package_root)

    dist_src = package_root / "dist"
    if not dist_src.exists():
        raise RuntimeError("codex-sdk build did not produce a dist directory.")

    shutil.copytree(dist_src, staging_dir / "dist")

    readme_src = package_root / "README.md"
    if readme_src.exists():
        copy_release_readme(readme_src, staging_dir / "README.md", package_names)

    license_src = REPO_ROOT / "LICENSE"
    if license_src.exists():
        shutil.copy2(license_src, staging_dir / "LICENSE")


def copy_native_binaries(
    vendor_src: Path,
    staging_dir: Path,
    components: list[str],
    target_filter: set[str] | None = None,
    allow_missing_components: set[str] | None = None,
) -> None:
    vendor_src = vendor_src.resolve()
    if not vendor_src.exists():
        raise RuntimeError(f"Vendor source directory not found: {vendor_src}")

    components_set = set(components)
    if not components_set:
        return
    allow_missing_components = allow_missing_components or set()

    vendor_dest = staging_dir / "vendor"
    if vendor_dest.exists():
        shutil.rmtree(vendor_dest)
    vendor_dest.mkdir(parents=True, exist_ok=True)

    copied_targets: set[str] = set()

    for target_dir in vendor_src.iterdir():
        if not target_dir.is_dir():
            continue

        if target_filter is not None and target_dir.name not in target_filter:
            continue

        copied_targets.add(target_dir.name)

        dest_target_dir = vendor_dest / target_dir.name

        if CODEX_PACKAGE_COMPONENT in components_set:
            if dest_target_dir.exists():
                shutil.rmtree(dest_target_dir)
            try:
                validate_codex_package_dir(target_dir)
            except RuntimeError:
                build_legacy_codex_package_layout(target_dir, dest_target_dir)
            else:
                dest_target_dir.mkdir(parents=True, exist_ok=True)
                for entry in CODEX_PACKAGE_ENTRIES:
                    src = target_dir / entry
                    dest = dest_target_dir / entry
                    if src.is_dir():
                        shutil.copytree(src, dest)
                    else:
                        shutil.copy2(src, dest)
        else:
            dest_target_dir.mkdir(parents=True, exist_ok=True)

        for component in components_set - {CODEX_PACKAGE_COMPONENT}:
            dest_dir_name = COMPONENT_DEST_DIR.get(component)
            if dest_dir_name is None:
                continue

            src_component_dir = target_dir / dest_dir_name
            if not src_component_dir.exists():
                if component in allow_missing_components:
                    continue
                raise RuntimeError(
                    f"Missing native component '{component}' in vendor source: {src_component_dir}"
                )

            dest_component_dir = dest_target_dir / dest_dir_name
            if dest_component_dir.exists():
                shutil.rmtree(dest_component_dir)
            shutil.copytree(src_component_dir, dest_component_dir)

    if target_filter is not None:
        missing_targets = sorted(target_filter - copied_targets)
        if missing_targets:
            missing_list = ", ".join(missing_targets)
            raise RuntimeError(f"Missing target directories in vendor source: {missing_list}")


def validate_codex_package_dir(package_dir: Path) -> None:
    is_windows = "windows" in package_dir.name
    required_files = [
        Path("codex-package.json"),
        Path("bin") / ("codex.exe" if is_windows else "codex"),
        Path("codex-path") / ("rg.exe" if is_windows else "rg"),
    ]

    if "linux" in package_dir.name:
        required_files.append(Path("codex-resources") / "bwrap")

    if is_windows:
        required_files.extend(
            [
                Path("codex-resources") / "codex-command-runner.exe",
                Path("codex-resources") / "codex-windows-sandbox-setup.exe",
            ]
        )

    missing_files = [
        str(relative_path)
        for relative_path in required_files
        if not (package_dir / relative_path).is_file()
    ]
    if missing_files:
        missing = ", ".join(missing_files)
        raise RuntimeError(f"Missing files in Codex package directory {package_dir}: {missing}")


def build_legacy_codex_package_layout(legacy_target_dir: Path, package_dir: Path) -> None:
    target = legacy_target_dir.name
    is_windows = "windows" in target
    exe_suffix = ".exe" if is_windows else ""
    package_dir.mkdir(parents=True)

    bin_dir = package_dir / "bin"
    resources_dir = package_dir / "codex-resources"
    path_dir = package_dir / "codex-path"
    bin_dir.mkdir()
    resources_dir.mkdir()
    path_dir.mkdir()

    shutil.copy2(
        legacy_target_dir / "codex" / f"codex{exe_suffix}",
        bin_dir / f"codex{exe_suffix}",
    )
    shutil.copy2(
        legacy_target_dir / "path" / f"rg{exe_suffix}",
        path_dir / f"rg{exe_suffix}",
    )

    if is_windows:
        for helper in [
            "codex-command-runner.exe",
            "codex-windows-sandbox-setup.exe",
        ]:
            shutil.copy2(legacy_target_dir / "codex" / helper, resources_dir / helper)
    elif "linux" in target:
        shutil.copy2(legacy_target_dir / "codex-resources" / "bwrap", resources_dir / "bwrap")

    with open(package_dir / "codex-package.json", "w", encoding="utf-8") as out:
        json.dump(
            {
                "layoutVersion": 1,
                "version": "unknown",
                "target": target,
                "variant": "codex",
                "entrypoint": f"bin/codex{exe_suffix}",
                "resourcesDir": "codex-resources",
                "pathDir": "codex-path",
            },
            out,
            indent=2,
        )
        out.write("\n")


def run_npm_pack(staging_dir: Path, output_path: Path) -> Path:
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="codex-npm-pack-") as pack_dir_str:
        pack_dir = Path(pack_dir_str)
        npm_cache_dir = pack_dir / "npm-cache"
        npm_logs_dir = pack_dir / "npm-logs"
        npm_cache_dir.mkdir()
        npm_logs_dir.mkdir()
        env = os.environ.copy()
        env["NPM_CONFIG_CACHE"] = str(npm_cache_dir)
        env["NPM_CONFIG_LOGS_DIR"] = str(npm_logs_dir)
        stdout = subprocess.check_output(
            ["npm", "pack", "--json", "--pack-destination", str(pack_dir)],
            cwd=staging_dir,
            env=env,
            text=True,
        )
        try:
            pack_output = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Failed to parse npm pack output.") from exc

        if not pack_output:
            raise RuntimeError("npm pack did not produce an output tarball.")

        tarball_name = pack_output[0].get("filename") or pack_output[0].get("name")
        if not tarball_name:
            raise RuntimeError("Unable to determine npm pack output filename.")

        tarball_path = pack_dir / tarball_name
        if not tarball_path.exists():
            raise RuntimeError(f"Expected npm pack output not found: {tarball_path}")

        shutil.move(str(tarball_path), output_path)

    return output_path


if __name__ == "__main__":
    import sys

    sys.exit(main())
