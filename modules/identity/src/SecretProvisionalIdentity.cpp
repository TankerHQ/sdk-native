#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <nlohmann/json.hpp>

#include <cppcodec/base64_rfc4648.hpp>

namespace Tanker
{
namespace Identity
{
SecretProvisionalIdentity createProvisionalIdentity(
    Trustchain::TrustchainId const& trustchainId, Email const& email)
{
  return SecretProvisionalIdentity{
      trustchainId,
      TargetType::Email,
      email.string(),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeEncryptionKeyPair(),
  };
}

std::string createProvisionalIdentity(std::string const& trustchainIdParam,
                                      Email const& email)
{
  if (email.empty())
    throw std::invalid_argument("Empty email");
  if (trustchainIdParam.empty())
    throw std::invalid_argument("Empty trustchainId");

  auto const trustchainId =
      cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(
          trustchainIdParam);
  return to_string(createProvisionalIdentity(trustchainId, email));
}

void from_json(nlohmann::json const& j, SecretProvisionalIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "email")
    throw std::runtime_error("unsupported provisional identity target: " +
                             target);

  identity = SecretProvisionalIdentity{
      j.at("trustchain_id").get<Trustchain::TrustchainId>(),
      TargetType::Email,
      j.at("value").get<std::string>(),
      {cppcodec::base64_rfc4648::decode<Crypto::PublicSignatureKey>(
           j.at("public_signature_key").get<std::string>()),
       cppcodec::base64_rfc4648::decode<Crypto::PrivateSignatureKey>(
           j.at("private_signature_key").get<std::string>())},
      {cppcodec::base64_rfc4648::decode<Crypto::PublicEncryptionKey>(
           j.at("public_encryption_key").get<std::string>()),
       cppcodec::base64_rfc4648::decode<Crypto::PrivateEncryptionKey>(
           j.at("private_encryption_key").get<std::string>())},
  };
}

void to_json(nlohmann::json& j, SecretProvisionalIdentity const& identity)
{
  if (identity.target != TargetType::Email)
    throw std::runtime_error("unsupported provisional identity target: " +
                             std::to_string(static_cast<int>(identity.target)));

  j["value"] = identity.value;
  j["trustchain_id"] = identity.trustchainId;
  j["target"] = "email";
  j["public_signature_key"] =
      cppcodec::base64_rfc4648::encode(identity.appSignatureKeyPair.publicKey);
  j["private_signature_key"] =
      cppcodec::base64_rfc4648::encode(identity.appSignatureKeyPair.privateKey);
  j["public_encryption_key"] =
      cppcodec::base64_rfc4648::encode(identity.appEncryptionKeyPair.publicKey);
  j["private_encryption_key"] = cppcodec::base64_rfc4648::encode(
      identity.appEncryptionKeyPair.privateKey);
}

std::string to_string(SecretProvisionalIdentity const& identity)
{
  return cppcodec::base64_rfc4648::encode(nlohmann::json(identity).dump());
}

SecretProvisionalIdentity createProvisionalIdentity(
    Trustchain::TrustchainId const& trustchainId, std::string const& email)
{
  return SecretProvisionalIdentity{
      trustchainId,
      TargetType::Email,
      email,
      Crypto::makeSignatureKeyPair(),
      Crypto::makeEncryptionKeyPair(),
  };
}

std::string createProvisionalIdentity(std::string const& strustchainId,
                                      std::string const& email)
{
  if (email.empty())
    throw std::invalid_argument("Empty email");
  if (strustchainId.empty())
    throw std::invalid_argument("Empty trustchainId");

  auto const trustchainId =
      cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(strustchainId);
  return to_string(createProvisionalIdentity(trustchainId, email));
}
}
}
