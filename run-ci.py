import argparse
import sys

import ci
import ci.android
import ci.cpp
import ci.ios
import ci.mail
import ci.git


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    build_and_test_parser = subparsers.add_parser("build-and-test")
    build_and_test_parser.add_argument("--profile", required=True)
    build_and_test_parser.add_argument("--bindings", action="store_true")
    build_and_test_parser.add_argument("--coverage", action="store_true")

    clean_cache_parser = subparsers.add_parser("clean-cache")

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument(
        "--profile", action="append", dest="profiles", required=True
    )
    deploy_parser.add_argument("--channel", default="stable")
    deploy_parser.add_argument("--user", default="tanker")
    deploy_parser.add_argument("--git-tag", required=True)

    subparsers.add_parser("nightly")
    subparsers.add_parser("mirror")

    platform = sys.platform.lower()
    ci.cpp.update_conan_config(platform)

    args = parser.parse_args()
    if args.command == "clean-cache":
        ci.cpp.clean_conan_cache()
    elif args.command == "build-and-test":
        ci.cpp.build_and_test(args.profile, args.bindings, args.coverage)
    elif args.command == "deploy":
        git_tag = args.git_tag
        version = ci.version_from_git_tag(git_tag)
        ci.bump_files(version)
        deployer = ci.cpp.Deployer(
            profiles=args.profiles, user="tanker", channel=args.channel
        )
        deployer.build(upload=True)
    elif args.command == "nightly":
        try:
            if platform == "linux":
                ci.android.check(native_from_sources=True)
            elif platform == "darwin":
                ci.ios.check(native_from_sources=True)
            else:
                sys.exit(f"Unknown platform: {platform}")
        except Exception as e:
            ci.mail.notify_nightly_failure("sdk-native")
            sys.exit(e)
    elif args.command == "mirror":
        ci.git.mirror(github_url="git@github.com:TankerHQ/sdk-native")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
