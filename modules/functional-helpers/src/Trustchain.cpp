#include <Tanker/Functional/Trustchain.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <mgs/base64.hpp>

#include <Helpers/Config.hpp>
#include <Helpers/Email.hpp>
#include <Helpers/PhoneNumber.hpp>

#include <memory>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Functional
{
void to_json(nlohmann::json& j, TrustchainConfig const& config)
{
  j["trustchainId"] = config.id;
  j["url"] = config.url;
  j["authToken"] = config.authToken;
  j["trustchainPrivateKey"] = config.privateKey;
}

void from_json(nlohmann::json const& j, TrustchainConfig& config)
{
  j.at("trustchainId").get_to(config.id);
  j.at("url").get_to(config.url);
  j.at("authToken").get_to(config.authToken);
  j.at("trustchainPrivateKey").get_to(config.privateKey);
}

Trustchain::Trustchain(std::string url,
                       Tanker::Trustchain::TrustchainId id,
                       std::string authToken,
                       Crypto::SignatureKeyPair keypair)
  : url(std::move(url)),
    id(std::move(id)),
    authToken(std::move(authToken)),
    keyPair(std::move(keypair))
{
}

Trustchain::Trustchain(TrustchainConfig const& config)
  : Trustchain(config.url,
               config.id,
               config.authToken,
               Crypto::makeSignatureKeyPair(config.privateKey))
{
}

User Trustchain::makeUser()
{
  auto const trustchainIdString = mgs::base64::encode(id);
  auto const trustchainPrivateKeyString =
      mgs::base64::encode(keyPair.privateKey);

  return User(url, trustchainIdString, trustchainPrivateKeyString);
}

AppProvisionalUser Trustchain::makeEmailProvisionalUser()
{
  auto const email = makeEmail();
  auto const secretProvisionalIdentity =
      SSecretProvisionalIdentity(Identity::createProvisionalIdentity(
          mgs::base64::encode(this->id), email));
  auto const publicProvisionalIdentity = SPublicIdentity(
      Identity::getPublicIdentity(secretProvisionalIdentity.string()));
  return AppProvisionalUser{
      email, secretProvisionalIdentity, publicProvisionalIdentity};
}

AppProvisionalUser Trustchain::makePhoneNumberProvisionalUser()
{
  auto const phoneNumber = makePhoneNumber();
  auto const secretProvisionalIdentity =
      SSecretProvisionalIdentity(Identity::createProvisionalIdentity(
          mgs::base64::encode(this->id), phoneNumber));
  auto const publicProvisionalIdentity = SPublicIdentity(
      Identity::getPublicIdentity(secretProvisionalIdentity.string()));
  return AppProvisionalUser{
      phoneNumber, secretProvisionalIdentity, publicProvisionalIdentity};
}

TrustchainConfig Trustchain::toConfig() const
{
  return {url, id, authToken, keyPair.privateKey};
}

Trustchain::Ptr Trustchain::make(TrustchainConfig const& config)
{
  return std::make_unique<Trustchain>(config);
}

Trustchain::Ptr Trustchain::make(std::string url,
                                 Tanker::Trustchain::TrustchainId id,
                                 std::string authToken,
                                 Crypto::SignatureKeyPair keypair)
{
  return std::make_unique<Trustchain>(
      std::move(url), std::move(id), std::move(authToken), std::move(keypair));
}
}
}
