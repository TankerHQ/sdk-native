from conans import ConanFile, CMake

class Compat(ConanFile):
    generators = "cmake", "ycm"

    def requirements(self):
        self.requires("tanker/1.10.0-r16@tanker/stable")
        self.requires("docopt.cpp/0.6.2@tanker/testing")
        self.requires("optional-lite/3.1.1@tanker/testing")
        # Must use exact revisions to avoid problems
        # Without it, 1.10.1 will use the latest revision of sqlpp11-connector-sqlite3/0.29,
        # compiled with sqlcipher/4.2.0, instead of using the old one (3.4.1)
        # FIXME The correct fix is to use lockfiles in dev, and release a new recipe for 1.10.1 based on lockfiles
        self.requires("Boost/1.68.0@tanker/testing#c559ba36a03e98246e6fbc6e4548761e")
        self.requires("sqlpp11-connector-sqlite3/0.29@tanker/testing#e6ca2a94ffd69227416772f919228190")

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()

