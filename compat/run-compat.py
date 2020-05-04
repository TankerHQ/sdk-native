import argparse
import cli_ui as ui
from path import Path
import tempfile
import ci.cpp
import ci.conan

import subprocess

TESTS = {
    "dev": [
        "encrypt",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.2.0": [
        "encrypt",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.1.0": [
        "encrypt",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.0.0": [
        "encrypt",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
}

CURRENT = "dev"


def build_all(profile):
    built_binary = {}
    for version, c in TESTS.items():
        ui.info(ui.darkblue, "building compat", version)
        src_path = Path.getcwd() / "compat" / version
        builder = ci.cpp.Builder(
            src_path,
            profile=profile,
            coverage=False,
            make_package=False,
            warn_as_error=False,
        )
        builder.install_deps()
        builder.configure()
        builder.build()
        built_binary[version] = builder.get_build_path() / "bin" / "compat"
    return built_binary


def run_test(base_path, next_path, version, command):
    with tempfile.TemporaryDirectory(prefix=f"{command}-") as tanker_dir:
        state_file = Path(tanker_dir) / "state.json"
        tc_config = Path(tanker_dir) / "trustchain-config.json"
        args = [
            command,
            f"--path={tanker_dir}",
            f"--state={state_file}",
            f"--tc-temp-config={tc_config}",
        ]
        base_command = [str(base_path), *args, "--base"]
        next_command = [str(next_path), *args, "--next"]
        ui.info(ui.darkblue, "running", *base_command)
        subprocess.run(base_command, check=True)
        ui.info(ui.darkblue, "running", *next_command)
        subprocess.run(next_command, check=True)
        ui.info(
            ui.green,
            ui.check,
            ui.green,
            "compat",
            command,
            version,
            "->",
            CURRENT,
            "success",
        )


def compat(profile: str) -> None:
    built_binary = build_all(profile=profile)

    ci.cpp.set_test_env()
    for version, commands in TESTS.items():
        for command in commands:
            if command not in TESTS[CURRENT]:
                continue
            run_test(built_binary[version], built_binary[CURRENT], version, command)


def export_tanker_dev(src_path: Path, profile: str) -> None:
    ci.conan.export(src_path=src_path, ref_or_channel="tanker/dev")


def use_packaged_tanker(src_path: Path, profile: str) -> None:
    builder = ci.cpp.Builder(
        src_path,
        profile=profile,
        coverage=False,
        make_package=False,
        warn_as_error=False,
    )
    builder.export_pkg("tanker/dev")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )
    parser.add_argument(
        "--export-tanker-dev",
        action="store_true",
        dest="export_tanker_dev",
        default=False,
    )
    parser.add_argument("--profile", required=True)

    args = parser.parse_args()
    if args.home_isolation:
        ci.conan.set_home_isolation()
        ci.conan.update_config()


    if args.export_tanker_dev:
        export_tanker_dev(Path.getcwd(), args.profile)
    else:
        use_packaged_tanker(Path.getcwd(), args.profile)

    compat(args.profile)


if __name__ == "__main__":
    main()
