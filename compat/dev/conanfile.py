from conans import ConanFile, CMake

class Compat(ConanFile):
    generators = "cmake", "ycm"
    settings = "build_type"

    def requirements(self):
        self.requires("tanker/dev@tanker/dev")
        self.requires("docopt.cpp/0.6.2")
        self.requires("boost/1.73.0")
        self.requires("mgs/0.1.1")

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()

