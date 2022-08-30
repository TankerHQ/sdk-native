import argparse
import json
import os
import platform
import shutil
import socket
import sys
from pathlib import Path
from typing import Dict, List, Optional

import cli_ui as ui  # noqa
import semver  # type: ignore
import tankerci
import tankerci.benchmark
import tankerci.cpp
import tankerci.git
import tankerci.reporting
from tankerci.conan import Profile


def build(profiles: List[Profile], coverage: bool, test: bool) -> None:
    build_profile = tankerci.conan.get_build_profile()
    for host_profile in profiles:

        build_path = tankerci.cpp.build(
            host_profile=host_profile,
            build_profile=build_profile,
            make_package=True,
            coverage=coverage,
        )
        if test:
            tankerci.cpp.check(build_path, coverage=coverage)
    recipe = Path.cwd() / "conanfile.py"
    shutil.copy(recipe, Path.cwd() / "package")


def benchmark_artifact(
    *, profiles: List[str], iterations: int, compare_results: bool, upload_results: bool
) -> None:
    for profile in profiles:
        bench_path = Path.cwd() / "bench-artifacts" / profile
        report_performance(
            profile=profile,
            bench_path=bench_path,
            iterations=iterations,
            compare_results=compare_results,
            upload_results=upload_results,
        )


def deploy(remote: str) -> None:
    # first, clear cache to avoid uploading trash
    tankerci.conan.run("remove", "*", "--force")

    artifacts_folder = Path.cwd() / "package"
    recipe = artifacts_folder / "conanfile.py"

    recipe_info = tankerci.conan.inspect(recipe)
    version = recipe_info["version"]

    profiles = [d.name for d in artifacts_folder.iterdir() if d.is_dir()]

    build_profile = tankerci.conan.get_build_profile()
    for profile in profiles:
        package_folder = artifacts_folder / profile
        host_profile = tankerci.conan.import_profile(
            package_folder / ".conan_profile.json"
        )
        tankerci.conan.export_pkg(
            recipe,
            package_folder=package_folder,
            host_profile=host_profile,
            build_profile=build_profile,
            force=True,
        )
    latest_reference = f"tanker/{version}@"
    alias = "tanker/latest-stable@"

    alias_info = tankerci.conan.inspect(recipe, want_alias_attribute=True)
    alias_version = alias_info["alias"].removeprefix("tanker/")
    is_newer_version = semver.gt(version, alias_version, loose=False)

    tankerci.conan.upload(latest_reference, remote=remote)
    if "alpha" not in version and "beta" not in version and is_newer_version:
        tankerci.conan.alias(alias, latest_reference)
        tankerci.conan.upload(alias, remote=remote)


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
    "linux-release": "linux-x86_64",
    "linux-release-shared": "linux-x86_64",
}


def fetch_lib_size_for_branch(branch: str) -> int:
    """Retrieves the size of the tanker shared library for a branch from InfluxDB"""
    response = tankerci.reporting.query_last_metrics(
        "benchmark",
        group_by="scenario",
        tags=["scenario"],
        fields=["value"],
        where={
            "branch": branch,
            "project": "sdk-native",
            "scenario": "size",
            "build-target": "linux-x86_64",
        },
    )
    result_series = response["results"][0]["series"][0]
    size_column_idx = result_series["columns"].index("value")
    size_data_point = result_series["values"][0][size_column_idx]
    return size_data_point


def report_performance(
    *,
    profile: str,
    bench_path: Path,
    iterations: int,
    compare_results: bool,
    upload_results: bool,
) -> None:
    branch = get_branch_name()
    if branch is None:
        ui.fatal("Not on a branch, can't report benchmarks")

    # Help mypy infering that branch is no longer of type Optional[str] but str
    assert branch is not None

    _, commit_id = tankerci.git.run_captured(Path.cwd(), "rev-parse", "HEAD")

    if profile not in BENCHMARK_PROFILE_TO_BUILD_TARGET:
        ui.fatal(f"We don't benchmark {profile}")

    bench_binary = bench_path / "bench_tanker"
    if platform.system() == "Windows":
        bench_binary = bench_binary.with_suffix(".exe")
    bench_output = bench_path / "benchmarks.json"

    if not bench_binary.exists():
        ui.fatal("No benchmark binary to run")

    tankerci.run(
        str(bench_binary),
        f"--benchmark_out={bench_output}",
        "--benchmark_out_format=json",
        f"--benchmark_repetitions={iterations}",
        "--benchmark_report_aggregates_only",
    )

    bench_results = json.loads(bench_output.read_text())
    if bench_results["context"]["library_build_type"] != "release":
        ui.fatal("Benchmark ran on a non-release build, check your config")

    if bench_results["context"]["cpu_scaling_enabled"]:
        ui.warning("This machine has CPU scaling enabled")

    hostname = os.environ.get("CI_RUNNER_DESCRIPTION", None)
    if not hostname:
        hostname = socket.gethostname()

    benchmark_aggregates: Dict[str, Dict[str, int]] = {}
    for benchmark in bench_results["benchmarks"]:
        name = benchmark["run_name"].lower()
        aggregate = benchmark["aggregate_name"]
        real_time = benchmark["real_time"]
        time_unit = benchmark["time_unit"]
        if time_unit == "ms":
            real_time /= 1000
        else:
            raise RuntimeError(f"unimplemented time unit: {time_unit}")
        if name not in benchmark_aggregates:
            benchmark_aggregates[name] = {}
        benchmark_aggregates[name][aggregate] = real_time

    # Post a comparison table to the merge request?
    if compare_results:
        response = tankerci.reporting.query_last_metrics(
            "benchmark",
            group_by="scenario",
            tags=["scenario"],
            fields=["real_time", "stddev"],
            where={"branch": "master", "project": "sdk-native"},
        )
        master_results = {}
        for point in response["results"][0]["series"]:
            result = tankerci.benchmark.data_point_to_bench_result(point)
            if result["stddev"] is None:
                result["stddev"] = 0  # Old benchmarks did not have a stddev
            master_results[result["name"]] = result

        master_size = fetch_lib_size_for_branch("master")
        new_size = fetch_lib_size_for_branch(branch)
        result_message = tankerci.benchmark.format_benchmark_table(
            benchmark_aggregates, master_results, master_size, new_size
        )

        tankerci.benchmark.post_gitlab_mr_message("sdk-native", result_message)

    # Save results to InfluxDB?
    if upload_results:
        for name, results in benchmark_aggregates.items():
            tankerci.reporting.send_metric(
                "benchmark",
                tags={
                    "project": "sdk-native",
                    "branch": branch,
                    "build-target": BENCHMARK_PROFILE_TO_BUILD_TARGET[profile],
                    "scenario": name,
                    "host": hostname,
                },
                fields={
                    "real_time": results["median"],
                    "stddev": results["stddev"],
                    "commit_id": commit_id,
                    "profile": profile,
                },
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

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument(
        "--profile",
        dest="profiles",
        action="append",
        nargs="+",
        type=str,
        required=True,
    )
    build_parser.add_argument("--coverage", action="store_true")
    build_parser.add_argument("--test", action="store_true")
    build_parser.add_argument("--remote", default="artifactory")

    benchmark_artifact_parser = subparsers.add_parser("benchmark-artifact")
    benchmark_artifact_parser.add_argument(
        "--profile", dest="profiles", action="append", required=True
    )
    benchmark_artifact_parser.add_argument(
        "--compare-results", dest="compare_results", action="store_true"
    )
    benchmark_artifact_parser.add_argument(
        "--upload-results", dest="upload_results", action="store_true"
    )
    benchmark_artifact_parser.add_argument("--iterations", default=20, type=int)

    bump_files_parser = subparsers.add_parser("bump-files")
    bump_files_parser.add_argument("--version", required=True)

    write_bridge_dotenv = subparsers.add_parser("write-bridge-dotenv")
    write_bridge_dotenv.add_argument(
        "--downstream", dest="downstreams", action="append", required=True
    )

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("--remote", default="artifactory")

    args = parser.parse_args()
    user_home = None
    if args.home_isolation:
        user_home = Path.cwd() / ".cache" / "conan" / args.remote

    if args.command == "build":
        with tankerci.conan.ConanContextManager([args.remote], conan_home=user_home):
            profiles = [Profile(p) for p in args.profiles]
            build(profiles, args.coverage, args.test)
    elif args.command == "benchmark-artifact":
        benchmark_artifact(
            profiles=args.profiles,
            iterations=args.iterations,
            compare_results=args.compare_results,
            upload_results=args.upload_results,
        )
    elif args.command == "bump-files":
        tankerci.bump_files(args.version)
    elif args.command == "deploy":
        native_release_version = os.environ.get("SDK_NATIVE_RELEASE_VERSION", None)
        if native_release_version is None:
            # We can't skip the job in .gitlab-ci because of 'needs' on it, so we do this check here
            ui.info("$SDK_NATIVE_RELEASE_VERSION is not set, nothing to deploy")
            sys.exit(0)

        with tankerci.conan.ConanContextManager(
            [args.remote],
            conan_home=user_home,
            clean_on_exit=True,
        ):
            deploy(args.remote)
    elif args.command == "write-bridge-dotenv":
        branches = [
            tankerci.git.matching_branch_or_default(repo) for repo in args.downstreams
        ]
        keys = [
            repo.replace("-", "_").upper() + "_BRIDGE_BRANCH"
            for repo in args.downstreams
        ]
        env_list = "\n".join([f"{k}={v}" for k, v in zip(keys, branches)])
        with open("bridge.env", "a+") as f:
            f.write(env_list)
        ui.info(env_list)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
