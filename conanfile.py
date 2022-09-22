from conans import tools, ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps
from conan.tools.layout import cmake_layout
from conan.tools.apple.apple import is_apple_os
import os


class TankerConan(ConanFile):
    name = "tanker"
    version = "dev"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "tankerlib_shared": [True, False],
        "fPIC": [True, False],
        "with_tracer": [True, False],
        "warn_as_error": [True, False],
        "sanitizer": ["address", "leak", "memory", "thread", "undefined", None],
        "coverage": [True, False],
        "with_coroutines_ts": [True, False],
        "with_http_backend": ["libcurl", None],
        "with_sqlite": [True, False],
    }
    default_options = {
        "tankerlib_shared": False,
        "fPIC": True,
        "with_tracer": False,
        "warn_as_error": False,
        "sanitizer": None,
        "coverage": False,
        "with_coroutines_ts": False,
        "with_http_backend": "libcurl",
        "with_sqlite": True,
    }
    generators = "CMakeDeps", "VirtualBuildEnv"
    exports_sources = "CMakeLists.txt", "modules/*", "cmake/*"

    @property
    def cross_building(self):
        return tools.cross_building(self)

    @property
    def should_build_tests(self):
        # develop is false when the package is used as a requirement,
        # so don't bother compiling tests in that case
        if not self.develop:
            return False

        # Usually, tests cannot be run when cross-compiling,
        # _except_ when cross-compiling from win64 to win32 with mingw
        # on Windows, so check for the special use case before
        # reading the value of `self.cross_building`
        if self.is_mingw and tools.os_info.is_windows:
            return True

        if self.cross_building:
            return False

        if not self.options.with_http_backend or not self.options.with_sqlite:
            return False

        return True

    @property
    def should_build_tools(self):
        # develop is false when the package is used as a requirement,
        # so don't bother compiling tools in that case
        if not self.develop:
            return False

        # mingw64 is not detected as cross-building
        if self.cross_building or self.is_mingw:
            return False

        return True

    @property
    def should_build_tracer(self):
        return self.options.with_tracer

    @property
    def sanitizer_flag(self):
        if self.options.sanitizer:
            return " -fsanitize=%s " % self.options.sanitizer
        return None

    @property
    def is_mingw(self):
        return self.settings.os == "Windows" and self.settings.compiler == "gcc"

    def requirements(self):
        private = self.options.tankerlib_shared

        self.requires("boost/1.78.0-r5", private=private)
        self.requires("libressl/3.5.3", private=private)
        self.requires("libcurl/7.80.0-r2", private=private)
        if self.options.with_sqlite:
            self.requires("sqlpp11/0.60-r3", private=private)
            self.requires("sqlpp11-connector-sqlite3/0.30-r3", private=private)
        self.requires("mgs/0.2.1-r1", private=private)
        self.requires("enum-flags/0.1a-r1", private=private)
        self.requires("range-v3/0.11.0-r4", private=private)
        self.requires("fmt/7.1.3-r2", private=private)
        self.requires("gsl-lite/0.37.0-r1", private=private)
        self.requires("nlohmann_json/3.10.5-r1", private=private)
        self.requires("libsodium/1.0.18-r1", private=private)
        self.requires("tconcurrent/0.40.0-r2", private=private)
        self.requires("date/3.0.0-r2", private=private)
        # catch2 is needed to export datastore tests
        self.requires("catch2/2.13.6-r2", private=private)
        if is_apple_os(self):
            self.requires("libcxx/11.1.0-r2", private=private)


    def build_requirements(self):
        if self.should_build_tools:
            self.test_requires("docopt.cpp/0.6.2-r2")
        if self.should_build_tests:
            self.test_requires("catch2-async/2.13.6-r3")
            self.test_requires("trompeloeil/38-r1")

    def generate(self):
        ct = CMakeToolchain(self)

        if self.options.sanitizer:
            ct.variables["CONAN_C_FLAGS"] += self.sanitizer_flag
            ct.variables["CONAN_CXX_FLAGS"] += self.sanitizer_flag
        if self.options.with_coroutines_ts:
            ct.variables["CONAN_CXX_FLAGS"] += " -fcoroutines-ts "
        ct.variables["BUILD_TESTS"] = self.should_build_tests
        ct.variables["WITH_TRACER"] = self.should_build_tracer
        ct.variables["WARN_AS_ERROR"] = self.options.warn_as_error
        ct.variables["BUILD_TANKER_TOOLS"] = self.should_build_tools
        ct.variables["TANKERLIB_SHARED"] = self.options.tankerlib_shared
        ct.variables["CMAKE_POSITION_INDEPENDENT_CODE"] = self.options.fPIC
        ct.variables["WITH_COVERAGE"] = self.options.coverage
        ct.variables["WITH_CURL"] = self.options.with_http_backend == "libcurl"
        ct.variables["WITH_SQLITE"] = self.options.with_sqlite

        ct.generate()

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install and self.develop:
            cmake.install()

    def deploy(self):
        self.copy("include/*")
        self.copy("*.a")
        self.copy("*.lib")
        self.copy("*.dll")
        self.copy("*.so")
        self.copy("*.dylib")
        if not self.options.tankerlib_shared:
            self.copy_deps("*.lib", dst="lib", keep_path=False)
            self.copy_deps("*.a", dst="lib", keep_path=False)

    def package(self):
        cmake = CMake(self)
        if self.settings.build_type == "Release" and not self.settings.os == "Windows":
            cmake.build(target="install/strip")
        else:
            cmake.install()

    def package_id(self):
        del self.info.options.warn_as_error

    def package_info(self):
        libs = ["ctanker", "tankerdatastoretests"]
        if not self.options.tankerlib_shared:
            libs.extend(
                [
                    "ctankerdatastore",
                    "tanker_async",
                    "tankerfunctionalhelpers",
                    "tankeradmin",
                    "tankertesthelpers",
                    "tankercore",
                    "tankerstreams",
                    "tankertrustchain",
                    "tankeridentity",
                    "tankercrypto",
                    "tankerserialization",
                    "tankererrors",
                    "tankerlog",
                    "tankerformat",
                    "tcurl",
                ]
            )

        if self.sanitizer_flag:
            self.cpp_info.sharedlinkflags = [self.sanitizer_flag]
            self.cpp_info.exelinkflags = [self.sanitizer_flag]

        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libs = libs
