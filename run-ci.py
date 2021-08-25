import argparse
import socket
import os
import shutil
import sys
import json
import platform
import math

from pathlib import Path
from typing import List, Optional, Any
import cli_ui as ui  # noqa
import tempfile
import gitlab

import tankerci
import tankerci.conan
import tankerci.cpp
import tankerci.git
import tankerci.reporting


def build_and_check(profiles: List[str], coverage: bool) -> None:
    for profile in profiles:
        build_path = tankerci.cpp.build(profile, make_package=True, coverage=coverage)
        report_size(profile, build_path)
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


def post_gitlab_mr_message(body: str) -> None:
    """Posts a comment on the Gitlab merge request for this pipeline"""
    gl = gitlab.Gitlab(
        os.environ["CI_SERVER_URL"], private_token=os.environ["GITLAB_TOKEN"]
    )
    gl.auth()
    p = gl.projects.get("TankerHQ/sdk-native")
    mr = p.mergerequests.get(os.environ["CI_MERGE_REQUEST_IID"])
    mr.discussions.create({"body": body})


def report_performance(
    *,
    profile: str,
    bench_path: Path,
    iterations: int,
    compare_results: bool,
    upload_results: bool,
) -> None:
    branch = get_branch_name()
    if not branch:
        ui.fatal("Not on a branch, can't report benchmarks")
    _, commit_id = tankerci.git.run_captured(os.getcwd(), "rev-parse", "HEAD")

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

    benchmark_aggregates = {}
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
            result = data_point_to_bench_result(point)
            if result["stddev"] is None:
                result["stddev"] = 0  # Old benchmarks did not have a stddev
            master_results[result["name"]] = result

        master_size = fetch_lib_size_for_branch("master")
        new_size = fetch_lib_size_for_branch(branch)
        result_message = format_benchmark_table(
            benchmark_aggregates, master_results, master_size, new_size
        )

        post_gitlab_mr_message(result_message)

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


def format_benchmark_change(ratio, stddev):
    """Formats the percentage change in a benchmark result row (with colors!)"""
    pctage = (ratio - 1) * 100
    confident_pctage_magnitude = max(abs(pctage) - stddev * 100, 0)
    confident_pctage = math.copysign(confident_pctage_magnitude, pctage)
    if confident_pctage <= -15:
        color = "green"
    elif confident_pctage <= -7.5:
        color = "greenyellow"
    elif confident_pctage >= 15:
        color = "red"
    elif confident_pctage >= 7.5:
        color = "pink"
    else:
        color = "default"

    ratio_str = f"{pctage:+.1f}\\%"
    stddev_str = f"± {stddev * 100:.1f}\\%"
    return r"$`\textcolor{%s}{\text{%s\scriptsize{ %s }}}`$" % (
        color,
        ratio_str,
        stddev_str,
    )


def format_benchmark_result(old_result, new_result):
    """Formats a single row of the benchmark results markdown table"""
    ratio = new_result["median"] / old_result["median"]
    stddev = ratio * math.sqrt(
        (new_result["stddev"] / new_result["median"]) ** 2
        + (old_result["stddev"] / old_result["median"]) ** 2
    )
    name = old_result["name"].replace("/real_time", "")
    old_time = (
        f"{old_result['median'] * 1000:.0f}ms ± {old_result['stddev'] * 1000:.0f}ms"
    )
    new_time = (
        f"{new_result['median'] * 1000:.0f}ms ± {new_result['stddev'] * 1000:.0f}ms"
    )
    diff = format_benchmark_change(ratio, stddev)
    return f"|{name}|{old_time}|{new_time}|{diff}|\n"


def format_benchmark_table(benchmark_aggregates, master_results, master_size, new_size):
    """Formats a markdown table containing benchmark results and size changes"""
    result_message = (
        "<details><summary>Benchmark results (lower is better)</summary>\n\n"
        "| Benchmark scenario | `master` | This MR | Difference |\n"
        "| --- | --- | --- | --- |\n"
    )

    size_diff_pct = 100 * (new_size / master_size - 1)
    result_message += f"| size | {master_size // 1024}kB | {new_size // 1024}kB | {size_diff_pct:+.1f}% |"

    for name, result in benchmark_aggregates.items():
        old_result = master_results[name]
        result_message += format_benchmark_result(old_result, result)
    return result_message


def data_point_to_bench_result(point: Any) -> Any:
    result = {}
    values = point["values"][0]
    for i, col in enumerate(point["columns"]):
        if col == "scenario":
            result["name"] = values[i].lower().replace('"', "")
        elif col == "real_time":
            result["median"] = values[i]
        else:
            result[col] = values[i]
    return result


SIZE_PROFILE_TO_BUILD_TARGET = {
    "android-armv7-release": "android-armv7",
    "android-armv8-release": "android-armv8",
    "android-x86_64-release": "android-x86_64",
    "android-x86-release": "android-x86",
    "linux-release-shared": "linux-x86_64",
    "macos-armv8-release-shared": "macos-armv8",
    "macos-x86_64-release-shared": "macos-x86_64",
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
        args = ["cmake", "--build", str(build_path)]
        if "vs2019" not in profile:
            args.extend(["--target", "install/strip"])
        else:
            args.extend(["--target", "install"])
        tankerci.run(
            *args, env={**os.environ, "DESTDIR": temp_path},
        )
        package_path = Path.cwd() / "package" / profile
        package_path_relative = package_path.relative_to(*package_path.parts[:1])
        if "vs2019" in profile:
            lib_path = temp_path / package_path_relative / "bin/ctanker.dll"
        elif "macos" in profile:
            lib_path = temp_path / package_path_relative / "lib/libctanker.dylib"
        else:
            lib_path = temp_path / package_path_relative / "lib/libctanker.so"
        size = lib_path.stat().st_size
        ui.info(f"Tanker library size: {size / 1024}KiB")
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

    subparsers.add_parser("deploy")

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()
        tankerci.conan.update_config()

    if args.command == "build-and-test":
        build_and_check(args.profiles, args.coverage)
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
        deploy()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
