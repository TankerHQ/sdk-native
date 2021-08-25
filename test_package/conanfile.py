from conans import ConanFile, CMake, tools
import os


class TankerNativeTestPackage(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "cmake"
    options = {"tankerlib_shared": [True, False]}
    default_options = "tankerlib_shared=False"

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
        if not tools.cross_building(self.settings):
            self.run(os.path.join("bin", "example"), run_environment=True)
