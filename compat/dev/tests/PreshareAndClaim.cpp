#include <Compat/Command.hpp>
#include <Compat/Helpers.hpp>
#include <Compat/States.hpp>

#include <Tanker/AsyncCore.hpp>

#include <Helpers/JsonFile.hpp>

using namespace std::string_literals;

struct PreshareAndClaim : Tanker::Compat::Command
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

    auto const clearData = "my love letter to bob "s;
    auto const encryptedData =
        encrypt(alice.core, clearData, {bobPublicProvisionalIdentity}, {});

    Tanker::saveJson(
        statePath,
        {{"bob_provisional_identity", bobProvisionalIdentity},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto bob = signUpAndClaim(json.at("bob_provisional_identity"),
                              "bob@tanker.io",
                              trustchain,
                              tankerPath);
    auto const encryptState = json.at("encrypt_state").get<EncryptState>();
    decrypt(bob.core, encryptState.encryptedData, encryptState.clearData);
  }
};

REGISTER_CMD(PreshareAndClaim,
             "preshare-and-claim",
             "encrypt then create a new user to claim and decrypt");
