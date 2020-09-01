#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>

#include <Helpers/Buffers.hpp>
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
    auto encryptedData =
        alice.core->encrypt(Tanker::make_buffer(clearData), {}, {sgroupId})
            .get();

    Tanker::saveJson(statePath,
                     ShareState{alice.user,
                                bob.user,
                                sgroupId,
                                EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto bobCore = signInUser(state.bob.identity, trustchain, tankerPath);
    decryptAndCheck(bobCore,
                    state.encryptState.encryptedData,
                    state.encryptState.clearData);

    auto aliceCore = signInUser(state.alice.identity, trustchain, tankerPath);
    decryptAndCheck(aliceCore,
                    state.encryptState.encryptedData,
                    state.encryptState.clearData);

    auto clearData = "my updated speech"s;
    auto encryptedData =
        aliceCore
            ->encrypt(
                Tanker::make_buffer(clearData), {}, {state.groupId.value()})
            .get();
    decryptAndCheck(bobCore, encryptedData, clearData);
  }
};

REGISTER_CMD(GroupCompat, "group", "simple encrypt then decrypt with a group");
