import argparse
import cli_ui as ui
from pathlib import Path
import tempfile
import tankerci.cpp
import tankerci.conan
import tankeradminsdk
import os
import json

import subprocess

CURRENT = "dev"

TESTS = {
    CURRENT: [
        "encrypt",
        "encryption-session",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.8.0": [
        "encrypt",
        "encryption-session",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.7.0": [
        "encrypt",
        "encryption-session",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.6.1": [
        "encrypt",
        "encryption-session",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.5.0": [
        "encrypt",
        "encryption-session",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
    "2.4.0": [
        "encrypt",
        "encryption-session",
        "group",
        "unlock",
        "preshare-and-claim",
        "decrypt-old-claim",
        "provisional-user-group-claim",
        "provisional-user-group-old-claim",
        "claim-provisional-self",
    ],
}


def assert_env(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"{name} should be set before running tests"
    return value


def compat_conan_home_path(version: str) -> Path:
    return Path.cwd() / "compat" / "conan" / version


def build_all(use_editable, profile):
    built_binary = {}
    for version, c in TESTS.items():
        ui.info(ui.darkblue, "building compat", version)
        src_path = Path.cwd() / "compat" / version
        tankerci.conan.set_home_isolation(compat_conan_home_path(version))
        tankerci.conan.config_install(str(src_path / "config"))
        if version == CURRENT:
            if use_editable:
                tankerci.conan.add_editable(Path.cwd())
            else:
                use_packaged_tanker(Path.cwd() / "package", profile)
        built_path = tankerci.cpp.build(profile, src_path=src_path)
        built_binary[version] = built_path / "bin" / "compat"
    return built_binary


def get_verification_code(app, email):
    return tankeradminsdk.get_verification_code(
        url=assert_env("TANKER_TRUSTCHAIND_URL"),
        app_id=app["id"],
        auth_token=app["auth_token"],
        email=email,
    )


def run_test(base_path, next_path, version, command):
    with tempfile.TemporaryDirectory(prefix=f"{command}-") as tanker_dir:
        admin = tankeradminsdk.Admin(
            url=assert_env("TANKER_ADMIND_URL"), id_token=assert_env("TANKER_ID_TOKEN")
        )
        app = admin.create_app("compat-native", is_test=True)
        bob_code = get_verification_code(app, "bob@tanker.io")
        tc_config = {
            "trustchainId": app["id"],
            "url": assert_env("TANKER_TRUSTCHAIND_URL"),
            "authToken": app["auth_token"],
            "trustchainPrivateKey": app["app_secret"],
        }
        tc_config_file = Path(tanker_dir) / "trustchain-config.json"
        tc_config_file.write_text(json.dumps(tc_config))

        state_file = Path(tanker_dir) / "state.json"
        args = [
            command,
            f"--path={tanker_dir}",
            f"--state={state_file}",
            f"--bob-code={bob_code}",
            f"--tc-temp-config={tc_config_file}",
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

        admin.delete_app(app["id"])


def compat(args: argparse.Namespace) -> None:
    built_binary = build_all(use_editable=args.use_editable, profile=args.profile)

    tankerci.cpp.set_test_env()
    for version, commands in TESTS.items():
        for command in commands:
            if command not in TESTS[CURRENT]:
                continue
            run_test(built_binary[version], built_binary[CURRENT], version, command)


def use_packaged_tanker(artifacts_path: Path, profile: str) -> None:
    tankerci.conan.export_pkg(
        artifacts_path,
        profile=profile,
        force=True,
        package_folder=artifacts_path / profile,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--use-editable", action="store_true", default=False,
    )
    parser.add_argument("--profile", required=True)

    args = parser.parse_args()

    compat(args)


if __name__ == "__main__":
    main()
