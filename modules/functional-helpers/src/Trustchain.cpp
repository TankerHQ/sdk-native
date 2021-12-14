#include <Tanker/Functional/Trustchain.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Types/Overloaded.hpp>

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
                       Crypto::PrivateSignatureKey privateSignatureKey)
  : url(std::move(url)),
    id(std::move(id)),
    authToken(std::move(authToken)),
    keyPair(Crypto::makeSignatureKeyPair(privateSignatureKey))
{
}

Trustchain::Trustchain(TrustchainConfig const& config)
  : Trustchain(config.url, config.id, config.authToken, config.privateKey)
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

tc::cotask<void> Trustchain::attachProvisionalIdentity(
    AsyncCore& session, AppProvisionalUser const& prov)
{
  auto const result =
      TC_AWAIT(session.attachProvisionalIdentity(prov.secretIdentity));
  if (result.status == Status::Ready)
    TC_RETURN();

  if (result.status != Status::IdentityVerificationNeeded)
    throw std::runtime_error("attachProvisionalIdentity: unexpected status!");

  auto const verif = TC_AWAIT(boost::variant2::visit(
      overloaded{
          [&](Email const& v) -> tc::cotask<Verification::Verification> {
            auto const verificationCode = TC_AWAIT(getVerificationCode(v));
            TC_RETURN(
                (Verification::ByEmail{v, VerificationCode{verificationCode}}));
          },
          [&](PhoneNumber const& v) -> tc::cotask<Verification::Verification> {
            auto const verificationCode = TC_AWAIT(getVerificationCode(v));
            TC_RETURN((Verification::ByPhoneNumber{
                v, VerificationCode{verificationCode}}));
          },
      },
      prov.value));
  TC_AWAIT(session.verifyProvisionalIdentity(verif));
}

TrustchainConfig Trustchain::toConfig() const
{
  return {url, id, authToken, keyPair.privateKey};
}

Trustchain::Ptr Trustchain::make(TrustchainConfig const& config)
{
  return std::make_unique<Trustchain>(config);
}

Trustchain::Ptr Trustchain::make(
    std::string url,
    Tanker::Trustchain::TrustchainId id,
    std::string authToken,
    Crypto::PrivateSignatureKey privateSignatureKey)
{
  return std::make_unique<Trustchain>(std::move(url),
                                      std::move(id),
                                      std::move(authToken),
                                      std::move(privateSignatureKey));
}
}
}
