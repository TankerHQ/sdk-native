import argparse
import socket
import os
import shutil
import sys
import json
import platform

from pathlib import Path
from typing import List, Optional
import cli_ui as ui  # noqa
import requests
import tempfile

import tankerci
import tankerci.conan
import tankerci.cpp
import tankerci.git
import tankerci.reporting


def build_and_check(profiles: List[str], coverage: bool) -> None:
    for profile in profiles:
        build_path = tankerci.cpp.build(
            profile,
            make_package=True,
            coverage=coverage,
        )
        report_size(profile, build_path)
        tankerci.cpp.check(build_path, coverage=coverage)
        report_performance(profile, build_path)
    recipe = Path.cwd() / "conanfile.py"
    shutil.copy(recipe, Path.cwd() / "package")


def deploy() -> None:
    # first, clear cache to avoid uploading trash
    tankerci.conan.run("remove", "*", "--force")

    artifacts_folder = Path.cwd() / "package"
    recipe = artifacts_folder / "conanfile.py"

    recipe_info = tankerci.conan.inspect(recipe)
    version = recipe_info["version"]

    profiles = [d.name for d in artifacts_folder.iterdir() if d.is_dir()]

    for profile in profiles:
        package_folder = artifacts_folder / profile
        tankerci.conan.export_pkg(
            recipe, package_folder=package_folder, profile=profile, force=True
        )
    latest_reference = f"tanker/{version}@"
    alias = "tanker/latest-stable@"
    tankerci.conan.upload(latest_reference)
    if "alpha" not in version and "beta" not in version:
        tankerci.conan.alias(alias, latest_reference)
        tankerci.conan.upload(alias)


def get_branch_name() -> Optional[str]:
    branch = os.environ.get("CI_COMMIT_BRANCH", None)
    if not branch:
        branch = os.environ.get("CI_COMMIT_REF_NAME", None)
    if not branch:
        branch = tankerci.git.get_current_branch(Path.cwd())
    if not branch:
        return None
    ui.info(f"Running on branch {branch}")
    return branch


BENCHMARK_PROFILE_TO_BUILD_TARGET = {
    "gcc8-release": "linux-x86_64",
    "gcc8-release-shared": "linux-x86_64",
}


def report_performance(profile: str, build_path: Path) -> None:
    branch = get_branch_name()
    if not branch:
        ui.info("Not on a branch, skipping benchmark report")
        return
    _, commit_id = tankerci.git.run_captured(os.getcwd(), "rev-parse", "HEAD")

    if profile not in BENCHMARK_PROFILE_TO_BUILD_TARGET:
        ui.info(f"We don't benchmark {profile}, skipping report")
        return

    bench_binary = build_path / "bin/bench_tanker"
    if platform.system() == "Windows":
        bench_binary = bench_binary.with_suffix(".exe")
    bench_output = build_path / "benchmarks.json"

    if not bench_binary.exists():
        ui.info("No benchmark to run, skipping benchmark report")
        return

    tankerci.run(
        str(bench_binary),
        f"--benchmark_out={bench_output}",
        "--benchmark_out_format=json",
    )

    bench_results = json.loads(bench_output.read_text())
    if bench_results["context"]["library_build_type"] != "release":
        ui.fatal("Benchmark ran on a non-release build, check your config")

    if bench_results["context"]["cpu_scaling_enabled"]:
        ui.warning("This machine has CPU scaling enabled")

    hostname = os.environ.get("CI_RUNNER_DESCRIPTION", None)
    if not hostname:
        hostname = socket.gethostname()

    for benchmark in bench_results["benchmarks"]:
        name = benchmark["name"]
        real_time = benchmark["real_time"]
        time_unit = benchmark["time_unit"]
        if time_unit == "ms":
            real_time /= 1000
        else:
            raise RuntimeError(f"unimplemented time unit: {time_unit}")
        tankerci.reporting.send_metric(
            "benchmark",
            tags={
                "project": "sdk-native",
                "branch": branch,
                "build-target": BENCHMARK_PROFILE_TO_BUILD_TARGET[profile],
                "scenario": name.lower(),
                "host": hostname,
            },
            fields={
                "real_time": real_time,
                "commit_id": commit_id,
                "profile": profile,
            },
        )


SIZE_PROFILE_TO_BUILD_TARGET = {
    "android-armv7-release": "android-armv7",
    "android-armv8-release": "android-armv8",
    "android-x86_64-release": "android-x86_64",
    "android-x86-release": "android-x86",
    "gcc8-release-shared": "linux-x86_64",
    "macos-release-shared": "macos-x86_64",
    "vs2019-release-shared": "windows-x86_64",
}


def report_size(profile: str, build_path: Path) -> None:
    if not tankerci.reporting.can_send_metrics():
        ui.info("InfluxDB environment variables not set, skipping metrics reporting")
        return

    if profile not in SIZE_PROFILE_TO_BUILD_TARGET:
        ui.info(f"We don't track SDK size with profile {profile}, skipping report")
        return

    branch = get_branch_name()
    if not branch:
        ui.info("Not on a branch, skipping report")
        return
    _, commit_id = tankerci.git.run_captured(os.getcwd(), "rev-parse", "HEAD")

    with tempfile.TemporaryDirectory() as temp_path:
        tankerci.run(
            "cmake",
            "--build",
            str(build_path),
            "--target",
            "install/strip",
            env={**os.environ, "DESTDIR": temp_path},
        )
        if "vs2019" in profile:
            lib_path = temp_path / build_path / "bin/ctanker.dll"
        elif "macos" in profile:
            lib_path = temp_path / build_path / "lib/libctanker.dylib"
        else:
            lib_path = temp_path / build_path / "lib/libctanker.so"
        size = lib_path.stat().st_size
        tankerci.reporting.send_metric(
            "benchmark",
            tags={
                "project": "sdk-native",
                "branch": branch,
                "build-target": SIZE_PROFILE_TO_BUILD_TARGET[profile],
                "scenario": "size",
            },
            fields={"value": size, "commit_id": commit_id, "profile": profile},
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )
    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    build_and_test_parser = subparsers.add_parser("build-and-test")
    build_and_test_parser.add_argument(
        "--profile", dest="profiles", action="append", required=True
    )
    build_and_test_parser.add_argument("--coverage", action="store_true")

    bump_files_parser = subparsers.add_parser("bump-files")
    bump_files_parser.add_argument("--version", required=True)

    subparsers.add_parser("deploy")
    subparsers.add_parser("mirror")

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()
        tankerci.conan.update_config()

    if args.command == "build-and-test":
        build_and_check(args.profiles, args.coverage)
    elif args.command == "bump-files":
        tankerci.bump_files(args.version)
    elif args.command == "deploy":
        deploy()
    elif args.command == "mirror":
        tankerci.git.mirror(github_url="git@github.com:TankerHQ/sdk-native", force=True)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
