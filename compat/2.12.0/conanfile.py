from conans import ConanFile, CMake


class Compat(ConanFile):
    generators = "cmake", "ycm"
    settings = "build_type"

    def requirements(self):
        # fmt: off
        self.requires("boost/1.73.0#ce452e6857c849e1987a06ce15d47810", override=True)
        self.requires("libressl/3.2.0#aeb7b8559636a40bc06f81026da9cb1a", override=True)
        self.requires("fetchpp/0.12.5#4ebe2601b0539ed84cffcd69cf38fd80", override=True)
        self.requires("nlohmann_json/3.8.0#a5aa536c8f57f0270dde99b4507f713b", override=True)
        self.requires("skyr-url/1.12.0#a81c3d36ffdab26b91a95b96645b2cac", override=True)
        self.requires("tl-expected/1.0.0#ed9219f96f9a22a8622de04deada455e", override=True)
        self.requires("range-v3/0.11.0#627399f4d170fffbb13a13ed96b69099", override=True)
        self.requires("sqlpp11/0.59#1ba232f47669b15d234daa3ee8f75ba3", override=True)
        self.requires("date/3.0.0#34088928612af8d27014fd69b0c340b2", override=True)
        self.requires("sqlpp11-connector-sqlite3/0.29#bd03093b51f67d6f9b2a7a5aeca3ed9a", override=True)
        self.requires("sqlcipher/4.4.0#58a289e248805c8ecf8ccc6919d935c7", override=True)
        self.requires("mgs/0.1.1#7e61da1ab254d213bab1a11b93d688ee", override=True)
        self.requires("enum-flags/0.1a#1465646923f26248b0ba3e0557221666", override=True)
        self.requires("fmt/7.0.2#4ea38ba34e73cf51fe92f7d0b6980567", override=True)
        self.requires("gsl-lite/0.37.0#244fadd18d97cb0d92a9d9de22b98346", override=True)
        self.requires("libsodium/1.0.18#7da1360fbd948094efe67ea00f61b751", override=True)
        self.requires("tconcurrent/0.34.0#bb0ea767341649c57592ddf3df90d452", override=True)
        self.requires("function2/4.1.0#dd821de6e3704caf6b50cdf27baf27c2", override=True)

        self.requires("tanker/2.12.0@")
        self.requires("docopt.cpp/0.6.2")
        # fmt: on

    def build(self):
        cmake = CMake(self)
        if self.should_configure:
            cmake.configure()
        if self.should_build:
            cmake.build()
        if self.should_install:
            cmake.install()
