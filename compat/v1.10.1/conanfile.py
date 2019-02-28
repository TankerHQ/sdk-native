from conans import ConanFile, CMake

class Compat(ConanFile):
    requires = "tanker/1.10.1-r15@tanker/stable", "docopt.cpp/0.6.2@tanker/testing", "Boost/1.68.0@tanker/testing"
    generators = "cmake", "ycm"

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()

