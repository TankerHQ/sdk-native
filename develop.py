import argparse
import sys

from path import Path

import ci
import ci.cpp
import ci.ios
import cli_ui as ui


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--isolate-conan-user-home", action="store_true", dest="home_isolation", default=False)

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    subparsers.add_parser("update-conan-config")
    configure_parser = subparsers.add_parser("configure")
    configure_parser.add_argument("--profile", required=True)
    configure_parser.add_argument(
        "--release", action="store_const", const="Release", dest="build_type"
    )
    configure_parser.add_argument("--coverage", action="store_true")
    configure_parser.set_defaults(build_type="Debug")

    args = parser.parse_args()
    if args.home_isolation:
        ci.cpp.set_home_isolation()
    command = args.command
    if command == "update-conan-config":
        ci.cpp.update_conan_config()
        return
    elif command == "configure":
        profile = args.profile
        coverage = args.coverage
        builder = ci.cpp.Builder(Path.getcwd(), profile=profile, coverage=coverage)
        builder.install_deps()
        builder.configure()

    else:
        parser.print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
