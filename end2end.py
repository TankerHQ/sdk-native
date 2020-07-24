import argparse

from path import Path
from conans import __version__ as conan_version

import tankerci.cpp
import tankerci.endtoend


def export_tanker_dev(src_path: Path) -> None:
    tankerci.conan.export(src_path=src_path, ref_or_channel="tanker/dev")


def use_packaged_tanker(src_path: Path, profile: str) -> None:
    builder = tankerci.cpp.Builder(
        src_path,
        profile=profile,
        make_package=False,
        coverage=False,
        warn_as_error=False,
    )
    builder.export_pkg("tanker/dev")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )
    parser.add_argument(
        "--export-tanker-dev",
        action="store_true",
        dest="export_tanker_dev",
        default=False,
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--use-local-sources", action="store_true", default=False)

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()

    tankerci.conan.update_config()

    if args.export_tanker_dev:
        export_tanker_dev(Path.getcwd())
    else:
        use_packaged_tanker(Path.getcwd(), args.profile)

    if args.use_local_sources:
        base_path = Path.getcwd().parent
    else:
        base_path = tankerci.git.prepare_sources(
            repos=["sdk-python", "sdk-js", "qa-python-js"]
        )
    tankerci.endtoend.test(
        tanker_conan_ref="tanker/dev@tanker/dev",
        profile=args.profile,
        base_path=base_path,
    )


if __name__ == "__main__":
    main()
