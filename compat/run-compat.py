import argparse
import cli_ui as ui
from path import Path
import tempfile
import ci.cpp

import subprocess

TESTS = {
    "v1.10.1": ["encrypt", "group", "unlock"],
    "dev":["encrypt", "group", "unlock"],
}

CURRENT = "dev"

def build_all(profile):
    built_binary = {}
    for version, c in TESTS.items():
        ui.info(ui.darkblue, "building compat", version)
        src_path = Path.getcwd() / "compat" / version
        builder = ci.cpp.Builder(src_path, profile=profile, coverage=False)
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
            f"--tc-temp-config={tc_config}"
        ]
        base_command = [str(base_path), *args, "--base"]
        next_command = [str(next_path), *args, "--next"]
        ui.info(ui.darkblue, "running", *base_command)
        subprocess.run(base_command, check=True)
        ui.info(ui.darkblue, "running", *next_command)
        subprocess.run(next_command, check=True)
        ui.info(ui.green, ui.check, ui.green, "compat", command, version, "->", CURRENT, "success")


def create_tanker_dev(profile: str) -> None:
    # fmt: off
    ci.cpp.run_conan(
            "create", ".",
            "compat/dev",
            "--profile", profile,
            "--update",
            "--build", "tanker"
            )
    # fmt: on


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--isolate-conan-user-home", action="store_true", dest="home_isolation", default=False)
    parser.add_argument("--profile", required=True)

    args = parser.parse_args()
    if args.home_isolation:
        ci.cpp.set_home_isolation()

    ci.cpp.update_conan_config()

    create_tanker_dev(args.profile)
    built_binary = build_all(profile=args.profile)

    old_tests = {k: v for k, v in TESTS.items() if k != CURRENT}
    ci.cpp.set_test_env()
    for version, commands in old_tests.items():
        for command in commands:
            if command not in TESTS[CURRENT]:
                continue
            run_test(built_binary[version], built_binary[CURRENT], version, command)

if __name__ == "__main__":
    main()
