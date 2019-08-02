import argparse
import os
import sys
import contextlib

from path import Path

import ci
import ci.android
import ci.conan
import ci.cpp
import ci.endtoend
import ci.git
import ci.ios


def build_and_check(profile: str, coverage: bool) -> None:
    built_path = ci.cpp.build(
        profile, make_package=True, coverage=coverage, warn_as_error=True
    )
    ci.cpp.check(built_path, coverage=coverage)


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
        ci.conan.set_home_isolation()

    ci.cpp.update_conan_config()

    if args.command == "build-and-test":
        build_and_check(args.profile, args.coverage)
    elif args.command == "nightly-build-emscripten":
        ci.cpp.build("emscripten")
    elif args.command == "deploy":
        git_tag = os.environ["CI_COMMIT_TAG"]
        version = ci.version_from_git_tag(git_tag)
        ci.bump_files(version)
        ci.cpp.build_recipe(
            Path.getcwd(),
            conan_reference=f"tanker/{version}@tanker/stable",
            upload=True,
        )
    elif args.command == "mirror":
        ci.git.mirror(github_url="git@github.com:TankerHQ/sdk-native")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
