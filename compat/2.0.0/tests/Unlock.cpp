#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>

#include <Helpers/JsonFile.hpp>

#include <boost/filesystem/operations.hpp>
#include <nlohmann/json.hpp>

using namespace std::string_literals;

struct UnlockCompat : Tanker::Compat::Command
{
  using Command::Command;

  void base() override
  {
    auto const alice = trustchain.makeUser();
    auto aliceCore = createCore(trustchain.url, trustchain.id, tankerPath);
    aliceCore->start(alice.identity).get();
    aliceCore->registerIdentity(Tanker::Passphrase{"my password"}).get();
    Tanker::saveJson(statePath,
                     {{"alice", alice}, {"password", "my password"}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const alice = upgradeToIdentity(
        trustchain.id, json.at("alice").get<Tanker::Test::User>());
    auto const passphrase = json.at("password").get<Tanker::Passphrase>();

    auto subDirForDevice = boost::filesystem::path(tankerPath) / "newDevice"s;
    boost::filesystem::create_directory(subDirForDevice);
    auto aliceCore =
        createCore(trustchain.url, trustchain.id, subDirForDevice.string());
    aliceCore->start(alice.identity).get();
    aliceCore->verifyIdentity(Tanker::Unlock::Verification{passphrase}).get();
    fmt::print("is open!\n");
  }
};

REGISTER_CMD(UnlockCompat, "unlock", "signup then unlock");
