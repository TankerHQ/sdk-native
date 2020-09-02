import argparse

from path import Path

import tankerci.cpp
import tankerci.conan
import tankerci.endtoend


def export_tanker(src_path: Path) -> None:
    tankerci.conan.export(src_path=src_path)


def use_packaged_tanker(src_path: Path, profile: str) -> None:
    builder = tankerci.cpp.Builder(
        src_path,
        profile=profile,
        make_package=False,
        coverage=False,
        warn_as_error=False,
    )
    builder.export_pkg()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )
    parser.add_argument(
        "--export-tanker",
        action="store_true",
        default=False,
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--use-local-sources", action="store_true", default=False)

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()

    tankerci.conan.update_config()

    if args.export_tanker:
        export_tanker(Path.getcwd())
    else:
        use_packaged_tanker(Path.getcwd(), args.profile)
    recipe_info = tankerci.conan.inspect(Path.getcwd())
    name = recipe_info["name"]
    version = recipe_info["version"]
    tanker_conan_ref = f"{name}/{version}@"

    if args.use_local_sources:
        base_path = Path.getcwd().parent
    else:
        base_path = tankerci.git.prepare_sources(
            repos=["sdk-python", "sdk-js", "qa-python-js"]
        )
    tankerci.endtoend.test(
        tanker_conan_ref=tanker_conan_ref,
        profile=args.profile,
        base_path=base_path,
    )


if __name__ == "__main__":
    main()
