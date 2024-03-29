from conans import ConanFile, tools
from conan.tools.cmake import CMake
from conan.tools.layout import cmake_layout
import os


class TankerNativeTestPackage(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeToolchain", "CMakeDeps"
    options = {"tankerlib_shared": [True, False]}
    default_options = {"tankerlib_shared": False}

    def layout(self):
        cmake_layout(self)

    def configure(self):
        del self.settings.compiler.libcxx

    def build(self):
        cmake = CMake(self)
        cmake.verbose = True
        cmake.configure()
        cmake.build()

    def imports(self):
        self.copy("*.dll", dst="bin", src="bin")
        self.copy("*.dylib", dst="bin", src="lib")
        self.copy("*.so.*", dst="bin", src="lib")
        self.copy("*.so", dst="bin", src="lib")

    def test(self):
        if not tools.cross_building(self):
            self.run(os.path.join(self.cpp.build.bindirs[0], "example"))
