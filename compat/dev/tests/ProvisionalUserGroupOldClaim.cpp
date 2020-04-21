
#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/JsonFile.hpp>

#include <nlohmann/json.hpp>

using namespace std::string_literals;

struct ProvisionalUserGroupOldClaim : Tanker::Compat::Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});
    auto const sgroupId =
        alice.core
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.user.identity)},
                 Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(
                     bobProvisionalIdentity)}})
            .get();
    auto const clearData = "My old allocution to the world";
    auto const encryptedData =
        alice.core->encrypt(Tanker::make_buffer(clearData), {}, {sgroupId})
            .get();

    auto bob = signUpAndClaim(
        Tanker::SSecretProvisionalIdentity{bobProvisionalIdentity},
        "bob@tanker.io",
        trustchain,
        tankerPath);

    Tanker::saveJson(
        statePath,
        IdentityShareState{bob.user.identity,
                           EncryptState{clearData, encryptedData}});
  }

  void next() override
  {
    auto const state = Tanker::loadJson(statePath).get<IdentityShareState>();
    auto bobCore = signInUser(state.identity, trustchain, tankerPath);
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);
  }
};

REGISTER_CMD(ProvisionalUserGroupOldClaim,
             "provisional-user-group-old-claim",
             "share with a group with provisional user and claim then decrypt");
