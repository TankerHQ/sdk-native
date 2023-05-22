import argparse

from pathlib import Path

import tankerci.cpp
import tankerci.conan
from tankerci.conan import TankerSource
import tankerci.js


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
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )
    parser.add_argument(
        "--use-tanker",
        type=TankerSource,
        default=TankerSource.EDITABLE,
        dest="tanker_source",
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--use-local-sources", action="store_true", default=False)
    parser.add_argument("--remote", default="artifactory")

    args = parser.parse_args()
    artifact_path = Path().cwd() / "package"
    user_home = None
    if args.home_isolation:
        user_home = Path.cwd() / ".cache" / "conan" / args.remote
        ctx = tankerci.conan.ConanContextManager([args.remote], conan_home=user_home)
        ctx.isolate()

    if args.use_local_sources:
        base_path = Path.cwd().parent
    else:
        base_path = tankerci.git.prepare_sources(
            repos=["sdk-python", "sdk-js", "qa-python-js"]
        )

    with tankerci.working_directory(base_path / "sdk-js"):
        tankerci.js.yarn_install()
        tankerci.js.run_yarn("build:all")

    with tankerci.working_directory(base_path / "sdk-python"):
        # artifacts are downloaded in sdk-native/package by gitlab
        # since we are using sdk-python we use this smoke grenade
        (Path.cwd() / "package").symlink_to(artifact_path)
        tankerci.run("poetry", "install", "--no-root")
        tankerci.run(
            "poetry",
            "run",
            "python",
            "run-ci.py",
            "prepare",
            f"--use-tanker={args.tanker_source.value}",
            f"--profile={args.profile}",
            f"--remote={args.remote}",
        )
        tankerci.run("poetry", "run", "python", "run-ci.py", "build")

    with tankerci.working_directory(base_path / "qa-python-js"):
        tankerci.run("poetry", "install")
        tankerci.run("poetry", "run", "pytest", "--verbose", "--capture=no")


if __name__ == "__main__":
    main()
