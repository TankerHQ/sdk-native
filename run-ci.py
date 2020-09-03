import argparse
import os
import sys

from typing import List
from path import Path

import tankerci
import tankerci.conan
import tankerci.cpp
import tankerci.git


def build_and_check(profiles: List[str], coverage: bool) -> None:
    for profile in profiles:
        built_path = tankerci.cpp.build(profile, make_package=True, coverage=coverage,)
        tankerci.cpp.check(built_path, coverage=coverage)
    recipe = Path.getcwd() / "conanfile.py"
    recipe.copy(Path.getcwd() / "package")


def deploy():
    # first, clear cache to avoid uploading trash
    tankerci.conan.run("remove", "*", "--force")

    artifacts_folder = Path.getcwd() / "package"
    recipe = artifacts_folder / "conanfile.py"

    recipe_info = tankerci.conan.inspect(recipe)
    version = recipe_info["version"]

    profiles = [d.basename() for d in artifacts_folder.dirs()]

    for profile in profiles:
        package_folder = artifacts_folder / profile
        tankerci.conan.export_pkg(
            recipe, package_folder=package_folder, profile=profile, force=True
        )
    tankerci.conan.upload(f"tanker/{version}@")
    git_tag = f"v{version}"
    tankerci.git.run(Path.getcwd(), "tag", git_tag)
    ssh_url = tankerci.context.get_gitlab_ssh_url()
    tankerci.git.run(Path.getcwd(), "push", f"{ssh_url}:Tanker/sdk-native", git_tag)


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
    elif args.command =="bump-files":
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
