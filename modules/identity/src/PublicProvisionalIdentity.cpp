#include <Tanker/Identity/PublicProvisionalIdentity.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>

#include <fmt/format.h>
#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
void from_json(nlohmann::json const& j, PublicProvisionalIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "email")
  {
    throw Errors::formatEx(Errc::InvalidProvisionalIdentityTarget,
                           "unsupported provisional identity target: {}",
                           target);
  }

  if (j.find("private_signature_key") != j.end())
  {
    throw Errors::Exception(Errc::InvalidType,
                            "cannot deserialize SecretProvisionalIdentity in "
                            "PublicProvisionalIdentity");
  }

  identity = PublicProvisionalIdentity{
      j.at("trustchain_id").get<Trustchain::TrustchainId>(),
      TargetType::Email,
      j.at("value").get<std::string>(),
      mgs::base64::decode<Crypto::PublicSignatureKey>(
          j.at("public_signature_key").get<std::string>()),
      mgs::base64::decode<Crypto::PublicEncryptionKey>(
          j.at("public_encryption_key").get<std::string>()),
  };
}

void to_json(nlohmann::ordered_json& j, PublicProvisionalIdentity const& identity)
{
  if (identity.target != TargetType::Email)
  {
    throw Errors::AssertionError(
        fmt::format("unsupported provisional identity target: {}",
                    static_cast<int>(identity.target)));
  }

  j["trustchain_id"] = identity.trustchainId;
  j["target"] = "email";
  j["value"] = identity.value;
  j["public_encryption_key"] =
      mgs::base64::encode(identity.appEncryptionPublicKey);
  j["public_signature_key"] =
      mgs::base64::encode(identity.appSignaturePublicKey);
}

std::string to_string(PublicProvisionalIdentity const& identity)
{
  return mgs::base64::encode(nlohmann::ordered_json(identity).dump());
}
}
}
