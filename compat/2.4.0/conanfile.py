from conans import ConanFile, CMake


class Compat(ConanFile):
    generators = "cmake", "ycm"
    settings = "build_type"

    def requirements(self):
        # fmt: off
        self.requires("Boost/1.71.0@tanker/testing#b46ed9a5025f9962b89f161f689257b3", override=True)
        self.requires("LibreSSL/2.9.2@tanker/testing#8c3b40f4e58e67b4b7359caea7b09173", override=True)
        self.requires("socket.io-client-cpp/1.6.3@tanker/testing#7a78105dcc480f14878eccaae87a4dde", override=True)
        self.requires("sqlpp11/0.58@tanker/testing#8113d286fd5d4a8b1122781b64eefb31", override=True)
        self.requires("sqlpp11-connector-sqlite3/0.29@tanker/testing#7b9f631fe420f2a6e90352d91fd6aba0", override=True)
        self.requires("cppcodec/edf46ab@tanker/testing#ab67bfdadc75781a3bbb01a2caf05e26", override=True)
        self.requires("enum-flags/0.1a@tanker/testing#8a2fb11871dcd1732ef3b036565cf4d7", override=True)
        self.requires("fmt/6.0.0#4d96273fe280a31be97d00fa14fa70b7", override=True)
        self.requires("gsl-lite/0.32.0@tanker/testing#8e9e0220b7a3c40458e5457c6d825bbf", override=True)
        self.requires("jsonformoderncpp/3.4.0@tanker/testing#3ba92ab5efa0ef0971af2f760eec7ee1", override=True)
        self.requires("libsodium/1.0.18@tanker/testing#f6a62ff8abf2171fcd2d7b845334a796", override=True)
        self.requires("tconcurrent/0.30.0@tanker/stable#481701a00b9e15d29d150f4c821617cb", override=True)
        self.requires("date/2.4.1@tanker/testing#95da0a6ae615b56ac0d0ffbcf43a08aa", override=True)
        self.requires("sqlcipher/4.2.0@tanker/testing#11dc58154e814db75e152c9612cd1bd2", override=True)

        self.requires("tanker/2.4.0@tanker/stable")
        self.requires("docopt.cpp/0.6.2@tanker/testing")
        # fmt: on

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()
