from conans import ConanFile, CMake

class Compat(ConanFile):
    generators = "cmake", "ycm"

    def requirements(self):
        self.requires("Boost/1.71.0@tanker/testing#2e8d459704e2077d4cf2d4556e4bdea9", override=True)
        self.requires("LibreSSL/2.9.2@tanker/testing#8c3b40f4e58e67b4b7359caea7b09173", override=True)
        self.requires("cppcodec/edf46ab@tanker/testing#ab67bfdadc75781a3bbb01a2caf05e26", override=True)
        self.requires("date/2.4.1@tanker/testing#95da0a6ae615b56ac0d0ffbcf43a08aa", override=True)
        self.requires("enum-flags/0.1a@tanker/testing#8a2fb11871dcd1732ef3b036565cf4d7", override=True)
        self.requires("fmt/5.3.0@bincrafters/stable#0", override=True)
        self.requires("gsl-lite/0.32.0@tanker/testing#8e9e0220b7a3c40458e5457c6d825bbf", override=True)
        self.requires("jsonformoderncpp/3.4.0@tanker/testing#3ba92ab5efa0ef0971af2f760eec7ee1", override=True)
        self.requires("libcurl/7.66.0@tanker/testing#bd25a356b94a4a5ce3f6b773161af1fe", override=True)
        self.requires("libsodium/1.0.18@tanker/testing#7aa196fbb924e597f8662bbe42d76323", override=True)
        self.requires("mockaron/0.9.4@tanker/stable#32dbf71b0527de93b9bb9e0e2cfe933a", override=True)
        self.requires("optional-lite/3.1.1@tanker/testing#56e84b7f8acd602d13181dcb960bd2b2", override=True)
        self.requires("socket.io-client-cpp/1.6.2@tanker/testing#46b96cce156739ac1036c424bb14407b", override=True)
        self.requires("sqlcipher/4.2.0@tanker/testing#11dc58154e814db75e152c9612cd1bd2", override=True)
        self.requires("sqlpp11/0.58@tanker/testing#8113d286fd5d4a8b1122781b64eefb31", override=True)
        self.requires("sqlpp11-connector-sqlite3/0.29@tanker/testing#7b9f631fe420f2a6e90352d91fd6aba0", override=True)
        self.requires("tconcurrent/0.28.1@tanker/stable#94cd0244a08759be57d01f593bbe9dfe", override=True)
        self.requires("zlib/1.2.11@conan/stable#0", override=True)

        self.requires("tanker/2.2.0@tanker/stable")
        self.requires("docopt.cpp/0.6.2@tanker/testing")

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()

