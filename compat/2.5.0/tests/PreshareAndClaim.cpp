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

struct PreshareAndClaim : Tanker::Compat::Command
{
  using Command::Command;

  void base() override
  {
    auto alice = signUpUser(trustchain, tankerPath);

    auto const bobProvisionalIdentity =
        Tanker::Identity::createProvisionalIdentity(
            mgs::base64::encode(trustchain.id), Tanker::Email{bobEmail});

    auto const bobPublicProvisionalIdentity = Tanker::SPublicIdentity{
        Tanker::Identity::getPublicIdentity(bobProvisionalIdentity)};

    auto const clearData = "my love letter to bob "s;
    auto const encryptedData = alice.core
                                   ->encrypt(Tanker::make_buffer(clearData),
                                             {bobPublicProvisionalIdentity},
                                             {})
                                   .get();

    Tanker::saveJson(
        statePath,
        {{"bob_provisional_identity", bobProvisionalIdentity},
         {"encrypt_state", EncryptState{clearData, encryptedData}}});
  }

  void next() override
  {
    auto const json = Tanker::loadJson(statePath);
    auto bob = signUpAndClaim(json.at("bob_provisional_identity"),
                              bobEmail,
                              bobCode,
                              trustchain,
                              tankerPath);
    auto const encryptState = json.at("encrypt_state").get<EncryptState>();
    decryptAndCheck(
        bob.core, encryptState.encryptedData, encryptState.clearData);
  }
};

REGISTER_CMD(PreshareAndClaim,
             "preshare-and-claim",
             "encrypt then create a new user to claim and decrypt");
