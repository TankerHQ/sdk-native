from conans import ConanFile, CMake

class Compat(ConanFile):
    generators = "cmake", "ycm"

    def requirements(self):
        self.requires("tanker/dev@tanker/dev")
        self.requires("docopt.cpp/0.6.2@tanker/testing")
        self.requires("Boost/1.68.0@tanker/testing")
        self.requires("cppcodec/edf46ab@tanker/testing")

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()

