
#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>

#include <Helpers/JsonFile.hpp>

#include <nlohmann/json.hpp>

using namespace std::string_literals;

struct ClaimProvisionalSelf : Tanker::Compat::Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            cppcodec::base64_rfc4648::encode(trustchain.id),
            Tanker::Email{bobEmail});

    auto const sgroupId =
        alice.core
            ->createGroup(
                {Tanker::SPublicIdentity{
                     Tanker::Identity::getPublicIdentity(alice.user.identity)},
                 Tanker::SPublicIdentity{Tanker::Identity::getPublicIdentity(
                     bobProvisionalIdentity)}})
            .get();

    auto bob = signUpUser(trustchain, tankerPath);

    auto const clearData = "My statement to the world";
    auto const encryptedData = encrypt(alice.core, clearData, {}, {sgroupId});

    // Force group verification
    encrypt(bob.core, "", {}, {sgroupId});

    Tanker::saveJson(
        statePath,
        {
            {"share_state",
             IdentityShareState{bob.user.identity,
                                EncryptState{clearData, encryptedData}}},
            {"provisional_identity", bobProvisionalIdentity},
        });
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto const state = json.at("share_state").get<IdentityShareState>();
    auto const provisionalIdentity =
        json.at("provisional_identity")
            .get<Tanker::SSecretProvisionalIdentity>();
    auto bobCore = signInUser(state.identity, trustchain, tankerPath);
    claim(bobCore, trustchain, provisionalIdentity, bobEmail, bobCode);
    decrypt(bobCore,
            state.encryptState.encryptedData,
            state.encryptState.clearData);
  }
};

REGISTER_CMD(
    ClaimProvisionalSelf,
    "claim-provisional-self",
    "share with a group with provisional user, a user shares with the group "
    "then this user claims and decrypts");
