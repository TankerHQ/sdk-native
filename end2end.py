import argparse

from path import Path

import tankerci.cpp
import tankerci.conan
import tankerci.endtoend


def use_packaged_tanker(artifacts_path: Path, profile: str) -> None:
    tankerci.conan.export_pkg(
        artifacts_path,
        profile=profile,
        force=True,
        package_folder=artifacts_path / profile,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )
    parser.add_argument(
        "--use-editable", action="store_true", default=False,
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--use-local-sources", action="store_true", default=False)

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()

    # tankerci.conan.update_config()

    tanker_conan_ref = "tanker/dev@"
    if args.use_editable:
        tankerci.conan.add_editable(Path().getcwd())
    else:
        artifacts_path = Path.getcwd() / "package"
        use_packaged_tanker(artifacts_path, args.profile)
        recipe_info = tankerci.conan.inspect(artifacts_path)
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
        tanker_conan_ref=tanker_conan_ref, profile=args.profile, base_path=base_path,
    )


if __name__ == "__main__":
    main()
