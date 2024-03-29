#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

using namespace Tanker::Trustchain;

namespace Tanker
{
namespace Identity
{
SecretProvisionalIdentity createProvisionalIdentity(TrustchainId const& trustchainId, Email const& email)
{
  return SecretProvisionalIdentity{
      trustchainId,
      TargetType::Email,
      email.string(),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeEncryptionKeyPair(),
  };
}

SecretProvisionalIdentity createProvisionalIdentity(TrustchainId const& trustchainId, PhoneNumber const& phoneNumber)
{
  return SecretProvisionalIdentity{
      trustchainId,
      TargetType::PhoneNumber,
      phoneNumber.string(),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeEncryptionKeyPair(),
  };
}

std::string createProvisionalIdentity(std::string const& trustchainIdParam, Email const& email)
{
  if (email.empty())
    throw Errors::Exception(Errc::InvalidEmail);
  if (trustchainIdParam.empty())
    throw Errors::Exception(Errc::InvalidTrustchainId);

  auto const trustchainId = mgs::base64::decode<TrustchainId>(trustchainIdParam);
  return to_string(createProvisionalIdentity(trustchainId, email));
}

std::string createProvisionalIdentity(std::string const& trustchainIdParam, PhoneNumber const& phoneNumber)
{
  if (phoneNumber.empty())
    throw Errors::Exception(Errc::InvalidPhoneNumber);
  if (trustchainIdParam.empty())
    throw Errors::Exception(Errc::InvalidTrustchainId);

  auto const trustchainId = mgs::base64::decode<TrustchainId>(trustchainIdParam);
  return to_string(createProvisionalIdentity(trustchainId, phoneNumber));
}

void from_json(nlohmann::json const& j, SecretProvisionalIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (!j.contains("private_signature_key"))
  {
    throw Errors::Exception(Errc::InvalidType,
                            "cannot deserialize PublicProvisionalIdentity in "
                            "SecretProvisionalIdentity");
  }
  if (target != "email" && target != "phone_number")
  {
    throw Errors::formatEx(
        Errc::InvalidProvisionalIdentityTarget, "unsupported provisional identity target: {}", target);
  }

  identity = SecretProvisionalIdentity{
      j.at("trustchain_id").get<TrustchainId>(),
      to_secret_target_type(target),
      j.at("value").get<std::string>(),
      {mgs::base64::decode<Crypto::PublicSignatureKey>(j.at("public_signature_key").get<std::string>()),
       mgs::base64::decode<Crypto::PrivateSignatureKey>(j.at("private_signature_key").get<std::string>())},
      {mgs::base64::decode<Crypto::PublicEncryptionKey>(j.at("public_encryption_key").get<std::string>()),
       mgs::base64::decode<Crypto::PrivateEncryptionKey>(j.at("private_encryption_key").get<std::string>())},
  };
}

void to_json(nlohmann::ordered_json& j, SecretProvisionalIdentity const& identity)
{
  if (identity.target != TargetType::Email && identity.target != TargetType::PhoneNumber)
  {
    throw Errors::formatEx(Errc::InvalidProvisionalIdentityTarget,
                           "unsupported provisional identity target: {}",
                           static_cast<int>(identity.target));
  }

  j["trustchain_id"] = identity.trustchainId;
  j["target"] = to_string(identity.target);
  j["value"] = identity.value;
  j["public_encryption_key"] = mgs::base64::encode(identity.appEncryptionKeyPair.publicKey);
  j["private_encryption_key"] = mgs::base64::encode(identity.appEncryptionKeyPair.privateKey);
  j["public_signature_key"] = mgs::base64::encode(identity.appSignatureKeyPair.publicKey);
  j["private_signature_key"] = mgs::base64::encode(identity.appSignatureKeyPair.privateKey);
}

std::string to_string(SecretProvisionalIdentity const& identity)
{
  return mgs::base64::encode(nlohmann::ordered_json(identity).dump());
}
}
}
