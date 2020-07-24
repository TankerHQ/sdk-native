import argparse
import os
import sys

from path import Path, TempDir
from conans import __version__ as conan_version

import tankerci
import tankerci.conan
import tankerci.cpp
import tankerci.git


def build_and_check(profile: str, coverage: bool) -> None:
    built_path = tankerci.cpp.build(
        profile, make_package=True, coverage=coverage,
    )
    tankerci.cpp.check(built_path, coverage=coverage)


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
    build_and_test_parser.add_argument("--profile", required=True)
    build_and_test_parser.add_argument("--coverage", action="store_true")

    subparsers.add_parser("deploy")
    subparsers.add_parser("mirror")
    subparsers.add_parser("nightly-build-emscripten")

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()

    tankerci.conan.update_config()

    if args.command == "build-and-test":
        build_and_check(args.profile, args.coverage)
    elif args.command == "nightly-build-emscripten":
        tankerci.cpp.build("emscripten")
    elif args.command == "deploy":
        git_tag = os.environ["CI_COMMIT_TAG"]
        version = tankerci.version_from_git_tag(git_tag)
        tankerci.bump_files(version)
        tankerci.cpp.build_recipe(
            Path.getcwd(),
            conan_reference=f"tanker/{version}@tanker/stable",
            upload=True,
        )
    elif args.command == "mirror":
        tankerci.git.mirror(github_url="git@github.com:TankerHQ/sdk-native", force=True)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
