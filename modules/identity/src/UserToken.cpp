#include <Tanker/Identity/UserToken.hpp>

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

#include <stdexcept>
#include <tuple>

namespace Tanker
{
namespace Identity
{
std::string generateUserToken(std::string const& trustchainIdString,
                              std::string const& trustchainPrivateKey,
                              SUserId const& userId)
{
  if (userId.empty())
    throw Errors::Exception(Errc::InvalidUserId);
  if (trustchainIdString.empty())
    throw Errors::Exception(Errc::InvalidTrustchainId);
  if (trustchainPrivateKey.empty())
    throw Errors::Exception(Errc::InvalidTrustchainPrivateKey);

  auto const trustchainId =
      mgs::base64::decode<Trustchain::TrustchainId>(
          trustchainIdString);
  return mgs::base64::encode(
      nlohmann::json(
          generateUserToken(
              mgs::base64::decode<
                  Tanker::Crypto::PrivateSignatureKey>(trustchainPrivateKey),
              Tanker::obfuscateUserId(userId, trustchainId)))
          .dump());
}

void from_json(nlohmann::json const& j, UserToken& result)
{
  j.at("user_id").get_to(result.delegation.userId);
  j.at("ephemeral_public_signature_key")
      .get_to(result.delegation.ephemeralKeyPair.publicKey);
  j.at("ephemeral_private_signature_key")
      .get_to(result.delegation.ephemeralKeyPair.privateKey);
  j.at("delegation_signature").get_to(result.delegation.signature);
  j.at("user_secret").get_to(result.userSecret);
}

void to_json(nlohmann::json& j, UserToken const& result)
{
  j["user_id"] = result.delegation.userId;
  j["ephemeral_public_signature_key"] =
      result.delegation.ephemeralKeyPair.publicKey;
  j["ephemeral_private_signature_key"] =
      result.delegation.ephemeralKeyPair.privateKey;
  j["delegation_signature"] = result.delegation.signature;
  j["user_secret"] = result.userSecret;
}

static_assert(sizeof(UserToken) == sizeof(Tanker::Crypto::SignatureKeyPair) +
                                       sizeof(Tanker::Crypto::Hash) * 2 +
                                       sizeof(Tanker::Crypto::Signature),
              "Update Operator ==");

bool operator==(UserToken const& lhs, UserToken const& rhs) noexcept
{
  return std::tie(lhs.delegation, lhs.userSecret) ==
         std::tie(rhs.delegation, rhs.userSecret);
}

bool operator!=(UserToken const& lhs, UserToken const& rhs) noexcept
{
  return !(lhs == rhs);
}
}
}
