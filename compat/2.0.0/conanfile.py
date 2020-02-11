from conans import ConanFile, CMake

class Compat(ConanFile):
    generators = "cmake", "ycm"

    def requirements(self):
        self.requires("Boost/1.68.0@tanker/testing#4cb14f2eda8f123bfd931366e04548f0", override=True)
        self.requires("LibreSSL/2.6.3@tanker/testing#aface7993904d5742d6fe4b516d23029", override=True)
        self.requires("cppcodec/edf46ab@tanker/testing#ab67bfdadc75781a3bbb01a2caf05e26", override=True)
        self.requires("date/2.4.1@tanker/testing#95da0a6ae615b56ac0d0ffbcf43a08aa", override=True)
        self.requires("enum-flags/0.1a@tanker/testing#8a2fb11871dcd1732ef3b036565cf4d7", override=True)
        self.requires("fmt/5.3.0@bincrafters/stable#0", override=True)
        self.requires("gsl-lite/0.32.0@tanker/testing#8e9e0220b7a3c40458e5457c6d825bbf", override=True)
        self.requires("jsonformoderncpp/3.4.0@tanker/testing#3ba92ab5efa0ef0971af2f760eec7ee1", override=True)
        self.requires("libsodium/1.0.16@tanker/testing#fa44463cc98b80c78471478ef7e97cab", override=True)
        self.requires("mockaron/0.9.2@tanker/stable#4b83a5a0046640e7998116d1a5c26b08", override=True)
        self.requires("optional-lite/3.1.1@tanker/testing#56e84b7f8acd602d13181dcb960bd2b2", override=True)
        self.requires("socket.io-client-cpp/1.6.1@tanker/testing#82b2653c19135259c12b0fdd414d598e", override=True)
        self.requires("sqlcipher/3.4.1@tanker/testing#0310579903faf075cf8c2b8b612dc54b", override=True)
        self.requires("sqlpp11/0.57@tanker/testing#5e532f7bad606453de88b7df65525166", override=True)
        self.requires("sqlpp11-connector-sqlite3/0.29@tanker/testing#e6ca2a94ffd69227416772f919228190", override=True)
        self.requires("tconcurrent/0.21.1@tanker/stable#431ad79c621f63d73d33961caa5ba4c5", override=True)
        self.requires("variant/1.3.0@tanker/testing#5b0b02419719401dc4ee5c0f37329106", override=True)

        self.requires("tanker/2.0.0@tanker/stable")
        self.requires("docopt.cpp/0.6.2@tanker/testing")

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()

