#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>

#include <Helpers/JsonFile.hpp>
#include <nlohmann/json.hpp>

using Tanker::Compat::Command;
struct EncryptCompat : Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);
    auto bob = signUpUser(trustchain, tankerPath);

    auto clearData = std::string("my confession to bob");
    auto encryptedData =
        encrypt(alice.core,
                clearData,
                {Tanker::SPublicIdentity{
                    Tanker::Identity::getPublicIdentity(bob.user.identity)}},
                {});

    Tanker::saveJson(statePath,
                     ShareState{alice.user,
                                bob.user,
                                nonstd::nullopt,
                                EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto alice = upgradeToIdentity(trustchain.id, state.alice);
    auto bob = upgradeToIdentity(trustchain.id, state.bob);

    auto bobCore = signInUser(bob.identity, trustchain, tankerPath);
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);

    auto aliceCore = signInUser(alice.identity, trustchain, tankerPath);
    decrypt(aliceCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);
  }
};
REGISTER_CMD(EncryptCompat,
             "encrypt",
             "simple encrypt then decrypt with a user");
