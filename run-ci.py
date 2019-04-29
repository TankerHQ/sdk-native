import argparse
import os
import sys

from path import Path

import ci
import ci.android
import ci.conan
import ci.cpp
import ci.endtoend
import ci.git
import ci.ios
import ci.mail


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--isolate-conan-user-home", action="store_true", dest="home_isolation", default=False)
    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    build_and_test_parser = subparsers.add_parser("build-and-test")
    build_and_test_parser.add_argument("--profile", required=True)
    build_and_test_parser.add_argument("--coverage", action="store_true")

    subparsers.add_parser("deploy")
    subparsers.add_parser("nightly")
    subparsers.add_parser("mirror")
    subparsers.add_parser("nightly-build-emscripten")
    subparsers.add_parser("e2e")

    args = parser.parse_args()
    if args.home_isolation:
        ci.conan.set_home_isolation()

    ci.cpp.update_conan_config()

    if args.command == "build-and-test":
        ci.cpp.check(args.profile, coverage=args.coverage, run_tests=True)
    elif args.command == "nightly-build-emscripten":
        with ci.mail.notify_failure("sdk-native"):
            ci.cpp.check("emscripten", run_tests=False)
    elif args.command == "deploy":
        git_tag = os.environ["CI_COMMIT_TAG"]
        version = ci.version_from_git_tag(git_tag)
        ci.bump_files(version)
        ci.cpp.build_recipe(
            Path.getcwd(),
            conan_reference=f"tanker/{version}@tanker/stable",
            upload=True,
        )
    elif args.command == "nightly":
        platform = sys.platform
        with ci.mail.notify_failure("sdk-native"):
            if platform == "linux":
                ci.android.check(native_from_sources=True)
            elif platform == "darwin":
                ci.ios.check(native_from_sources=True)
            else:
                sys.exit(f"Unknown platform: {platform}")
    elif args.command == "mirror":
        ci.git.mirror(github_url="git@github.com:TankerHQ/sdk-native")
    elif args.command == "e2e":
        ci.endtoend.test(env="dev")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
