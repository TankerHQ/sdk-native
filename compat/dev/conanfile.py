from conans import ConanFile, CMake

class Compat(ConanFile):
    requires = "tanker/dev@compat/dev", "docopt.cpp/0.6.2@tanker/testing", "Boost/1.68.0@tanker/testing"
    generators = "cmake", "ycm"

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()

