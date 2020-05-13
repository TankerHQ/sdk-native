#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>

#include <Helpers/Buffers.hpp>
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
        alice.core
            ->encrypt(
                Tanker::make_buffer(clearData),
                {Tanker::SPublicIdentity{
                    Tanker::Identity::getPublicIdentity(bob.user.identity)}},
                {})
            .get();

    Tanker::saveJson(statePath,
                     ShareState{alice.user,
                                bob.user,
                                std::nullopt,
                                EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto alice = upgradeToIdentity(trustchain.id, state.alice);
    auto bob = upgradeToIdentity(trustchain.id, state.bob);

    auto bobCore = signInUser(bob.identity, trustchain, tankerPath);
    decryptAndCheck(bobCore,
                    state.encryptState.encryptedData,
                    state.encryptState.clearData);

    auto aliceCore = signInUser(alice.identity, trustchain, tankerPath);
    decryptAndCheck(aliceCore,
                    state.encryptState.encryptedData,
                    state.encryptState.clearData);
  }
};
REGISTER_CMD(EncryptCompat,
             "encrypt",
             "simple encrypt then decrypt with a user");
