#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>

#include <Helpers/JsonFile.hpp>
#include <nlohmann/json.hpp>

using namespace std::string_literals;

struct GroupCompat : Tanker::Compat::Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bob = signUpUser(trustchain, tankerPath);
    bob.core->stop().get();

    auto sgroupId =
        alice.core
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.user.identity)},
                 Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(bob.user.identity)}})
            .get();

    auto clearData = "my little speech"s;
    auto encryptedData = encrypt(alice.core, clearData, {}, {sgroupId});

    Tanker::saveJson(statePath,
                     ShareState{alice.user,
                                bob.user,
                                sgroupId,
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

    auto clearData = "my updated speech"s;
    auto encryptedData =
        encrypt(aliceCore, clearData, {}, {state.groupId.value()});
    decrypt(bobCore, encryptedData, clearData);
  }
};

REGISTER_CMD(GroupCompat, "group", "simple encrypt then decrypt with a group");
