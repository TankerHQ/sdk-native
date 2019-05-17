#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>

#include <Helpers/JsonFile.hpp>

using namespace std::string_literals;

struct DecryptOldClaim : Tanker::Compat::Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{"bob@tanker.io"});
    auto const bobPublicProvisionalIdentity = Tanker::SPublicIdentity{
        Tanker::Identity::getPublicIdentity(bobProvisionalIdentity)};
    auto const clearData = "my love letter to bob"s;
    auto const encryptedData =
        encrypt(alice.core, clearData, {bobPublicProvisionalIdentity}, {});

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

REGISTER_CMD(DecryptOldClaim,
             "decrypt-old-claim",
             "signup, claim and share with this user then decrypt");
