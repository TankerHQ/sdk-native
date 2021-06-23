#include <Tanker/Identity/PublicProvisionalIdentity.hpp>

#include <Tanker/Crypto/Crypto.hpp>
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

  if (j.find("private_signature_key") != j.end())
  {
    throw Errors::Exception(Errc::InvalidType,
                            "cannot deserialize SecretProvisionalIdentity in "
                            "PublicProvisionalIdentity");
  }

  identity = PublicProvisionalIdentity{
      j.at("trustchain_id").get<Trustchain::TrustchainId>(),
      to_target_type(target),
      j.at("value").get<std::string>(),
      mgs::base64::decode<Crypto::PublicSignatureKey>(
          j.at("public_signature_key").get<std::string>()),
      mgs::base64::decode<Crypto::PublicEncryptionKey>(
          j.at("public_encryption_key").get<std::string>()),
  };
}

void to_json(nlohmann::ordered_json& j, PublicProvisionalIdentity const& identity)
{
  j["trustchain_id"] = identity.trustchainId;
  j["target"] = to_string(identity.target);
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

Crypto::Hash hashProvisionalEmail(std::string const& value)
{
  return Crypto::generichash(
      gsl::make_span(value).template as_span<std::uint8_t const>());
}
}
}
