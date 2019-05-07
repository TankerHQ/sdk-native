#include <Tanker/Identity/PublicProvisionalIdentity.hpp>

#include <nlohmann/json.hpp>

#include <cppcodec/base64_rfc4648.hpp>

namespace Tanker
{
namespace Identity
{
void from_json(nlohmann::json const& j, PublicProvisionalIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "email")
    throw std::runtime_error("unsupported provisional identity target: " +
                             target);

  if (j.find("private_signature_key") != j.end())
  {
    throw std::invalid_argument(
        "Cannot deserialize SecretProvisionalIdentity in "
        "PublicProvisionalIdentity");
  }

  identity = PublicProvisionalIdentity{
      j.at("trustchain_id").get<Trustchain::TrustchainId>(),
      TargetType::Email,
      j.at("value").get<std::string>(),
      cppcodec::base64_rfc4648::decode<Crypto::PublicSignatureKey>(
          j.at("public_signature_key").get<std::string>()),
      cppcodec::base64_rfc4648::decode<Crypto::PublicEncryptionKey>(
          j.at("public_encryption_key").get<std::string>()),
  };
}

void to_json(nlohmann::json& j, PublicProvisionalIdentity const& identity)
{
  if (identity.target != TargetType::Email)
    throw std::runtime_error("unsupported provisional identity target: " +
                             std::to_string(static_cast<int>(identity.target)));

  j["value"] = identity.value;
  j["trustchain_id"] = identity.trustchainId;
  j["target"] = "email";
  j["public_signature_key"] =
      cppcodec::base64_rfc4648::encode(identity.appSignaturePublicKey);
  j["public_encryption_key"] =
      cppcodec::base64_rfc4648::encode(identity.appEncryptionPublicKey);
}

std::string to_string(PublicProvisionalIdentity const& identity)
{
  return cppcodec::base64_rfc4648::encode(nlohmann::json(identity).dump());
}
}
}
