import argparse
import sys

from path import Path

import ci
import ci.cpp
import ci.ios
import cli_ui as ui


def main() -> None:
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    subparsers.add_parser("update-conan-config")
    configure_parser = subparsers.add_parser("configure")
    configure_parser.add_argument("--profile", required=True)
    configure_parser.add_argument("--release", action="store_const", const="Release", dest="build_type")
    configure_parser.add_argument("--coverage", action="store_true")
    configure_parser.set_defaults(build_type="Debug")

    args = parser.parse_args()
    command = args.command
    if command == "update-conan-config":
        ci.cpp.update_conan_config(sys.platform)
        return
    elif command == "configure":
        profile = args.profile
        build_type = args.build_type
        coverage = args.coverage
        builder = ci.cpp.Builder(profile, coverage=coverage)
        builder.build_type = build_type
        builder.install_deps()
        builder.configure()

    else:
        parser.print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
