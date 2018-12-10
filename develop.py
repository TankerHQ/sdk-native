import argparse
import sys

from path import Path

import ci
import ci.cpp
import ci.ios
import ui


def main() -> None:
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    subparsers.add_parser("update-conan-config")

    args = parser.parse_args()
    if args.command == "update-conan-config":
        ci.cpp.update_conan_config(sys.platform)
        return
    else:
        parser.print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
