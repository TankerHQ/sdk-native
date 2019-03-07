from conans import ConanFile, CMake, tools
import os


class TankerNativeTestPackage(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "cmake"
    options = {
        "tankerlib_shared": [True, False]
    }
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
        if tools.cross_building(self.settings):
            assert(os.path.exists(os.path.join("bin", "example")))
            return
        env = ""
        if self.options.tankerlib_shared:
            if self.settings.os == "Macos":
                env = "DYLD_FALLBACK_LIBRARY_PATH= DYLD_LIBRARY_PATH=./bin"
            elif self.settings.os == "Linux":
                env = "LD_LIBRARY_PATH=./bin"
        exec_path = os.path.join('bin', 'example')
        self.run("%s %s" % (env, exec_path))
