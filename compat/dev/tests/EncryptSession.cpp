#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/JsonFile.hpp>

#include <nlohmann/json.hpp>

using Tanker::Compat::Command;
struct EncryptSession : Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto clearData = std::string("my confession to bob");
    auto encryptionSession = alice.core->makeEncryptionSession({}, {}).get();
    std::vector<uint8_t> encryptedData(
        Tanker::EncryptionSession::encryptedSize(clearData.size()));
    tc::async_resumable([&]() -> tc::cotask<void> {
      TC_AWAIT(encryptionSession.encrypt(encryptedData.data(),
                                         Tanker::make_buffer(clearData)));
    }).get();

    Tanker::saveJson(statePath,
                     ShareState{alice.user,
                                {},
                                std::nullopt,
                                EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<ShareState>();

    auto alice = upgradeToIdentity(trustchain.id, state.alice);

    auto aliceCore = signInUser(alice.identity, trustchain, tankerPath);
    decryptAndCheck(aliceCore,
                    state.encryptState.encryptedData,
                    state.encryptState.clearData);
  }
};
REGISTER_CMD(EncryptSession,
             "encryptSession",
             "encrypt in a session then decrypt");
