#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>

#include <Helpers/JsonFile.hpp>

#include <boost/filesystem/operations.hpp>

using namespace std::string_literals;

struct UnlockCompat : Tanker::Compat::Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain.makeUser();
    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->start(alice.identity).get();
    aliceCore->registerIdentity(Tanker::Password{"my password"}).get();
    Tanker::saveJson(statePath,
                     {{"alice", alice}, {"password", "my password"}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const alice = upgradeToIdentity(
        trustchain.id, json.at("alice").get<Tanker::Test::User>());
    auto const password = json.at("password").get<Tanker::Password>();

    auto subDirForDevice = boost::filesystem::path(tankerPath) / "newDevice"s;
    boost::filesystem::create_directory(subDirForDevice);
    auto aliceCore =
        createCore(trustchain.url, trustchain.id, subDirForDevice.string());
    aliceCore->start(alice.identity).get();
    aliceCore->verifyIdentity(Tanker::Unlock::Verification{password}).get();
    fmt::print("is open!\n");
  }
};

REGISTER_CMD(UnlockCompat, "unlock", "signup then unlock");
