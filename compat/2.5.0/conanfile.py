from conans import ConanFile, CMake


class Compat(ConanFile):
    generators = "cmake", "ycm"
    settings = "build_type"

    def requirements(self):
        # fmt: off
        self.requires("boost/1.73.0#2bf7bf4dfffe111f39efe346e33e5b8f", override=True)
        self.requires("libressl/3.2.0#aeb7b8559636a40bc06f81026da9cb1a", override=True)
        self.requires("socket.io-client-cpp/1.6.6#9091d11f7d9dcf3c18856c515f72de68", override=True)
        self.requires("sqlpp11/0.59#1ba232f47669b15d234daa3ee8f75ba3", override=True)
        self.requires("sqlpp11-connector-sqlite3/0.29#bd03093b51f67d6f9b2a7a5aeca3ed9a", override=True)
        self.requires("enum-flags/0.1a#1465646923f26248b0ba3e0557221666", override=True)
        self.requires("fmt/6.2.1#a44304a82c2ea50ad19308f2592d7a57", override=True)
        self.requires("gsl-lite/0.36.0#23b108e79947b0bd460a59cf12943fd1", override=True)
        self.requires("jsonformoderncpp/3.8.0@tanker/testing#a5aa536c8f57f0270dde99b4507f713b", override=True)
        self.requires("libsodium/1.0.18#6f0202333b694cd2eff8f4eb2cf741db", override=True)
        self.requires("tconcurrent/0.31.2#5a162e91f2bd69f9e7b101aa6034164b", override=True)
        self.requires("date/3.0.0#34088928612af8d27014fd69b0c340b2", override=True)
        self.requires("sqlcipher/4.4.0#58a289e248805c8ecf8ccc6919d935c7", override=True)
        self.requires("fetchpp/0.8.1#5362e20e14b17209d6ae0bc4cabce4e4", override=True)
        self.requires("mgs/0.1.1#7e61da1ab254d213bab1a11b93d688ee", override=True)
        self.requires("skyr-url/1.11.0#7b6eed1638c842d81ac6bb51969624b4", override=True)
        self.requires("tl-expected/1.0.0#ed9219f96f9a22a8622de04deada455e", override=True)


        self.requires("tanker/2.5.0@tanker/stable")
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
