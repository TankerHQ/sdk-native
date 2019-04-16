#include <Tanker/Identity/SecretPermanentIdentity.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/Utils.hpp>

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{

SecretPermanentIdentity::SecretPermanentIdentity(
    UserToken const& userToken, TrustchainId const& trustchainId)
  : UserToken(userToken), trustchainId(trustchainId)
{
}

SecretPermanentIdentity createIdentity(
    TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& trustchainPrivateKey,
    Trustchain::UserId const& userId)
{
  return SecretPermanentIdentity(
      generateUserToken(trustchainPrivateKey, userId), std::move(trustchainId));
}

std::string createIdentity(std::string const& trustchainIdParam,
                           std::string const& trustchainPrivateKey,
                           SUserId const& userId)
{
  if (userId.empty())
    throw std::invalid_argument("Empty userId");
  if (trustchainIdParam.empty())
    throw std::invalid_argument("Empty trustchainId");
  if (trustchainPrivateKey.empty())
    throw std::invalid_argument("Empty trustchainPrivateKey");

  auto const trustchainId =
      cppcodec::base64_rfc4648::decode<TrustchainId>(trustchainIdParam);
  return to_string(createIdentity(
      trustchainId,
      cppcodec::base64_rfc4648::decode<Tanker::Crypto::PrivateSignatureKey>(
          trustchainPrivateKey),
      Tanker::obfuscateUserId(userId, trustchainId)));
}

SecretPermanentIdentity upgradeUserToken(TrustchainId const& trustchainId,
                                         Trustchain::UserId const& userId,
                                         UserToken const& userToken)
{
  if (userToken.delegation.userId != userId)
    throw std::invalid_argument("Wrong userId provided");
  return SecretPermanentIdentity(std::move(userToken), std::move(trustchainId));
}

std::string upgradeUserToken(std::string const& strustchainId,
                             SUserId const& suserId,
                             std::string const& suserToken)
{
  auto const trustchainId =
      cppcodec::base64_rfc4648::decode<TrustchainId>(strustchainId);
  auto const userId = Tanker::obfuscateUserId(suserId, trustchainId);
  auto const userToken = extract<UserToken>(suserToken);
  return to_string(upgradeUserToken(trustchainId, userId, userToken));
}

void from_json(nlohmann::json const& j, SecretPermanentIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "user")
    throw std::invalid_argument(
        "failed to deserialize secret permanent identity");
  j.at("trustchain_id").get_to(identity.trustchainId);
  j.at("value").get_to(identity.delegation.userId);
  j.at("user_secret").get_to(identity.userSecret);
  j.at("ephemeral_public_signature_key")
      .get_to(identity.delegation.ephemeralKeyPair.publicKey);
  j.at("ephemeral_private_signature_key")
      .get_to(identity.delegation.ephemeralKeyPair.privateKey);
  j.at("delegation_signature").get_to(identity.delegation.signature);
}

void to_json(nlohmann::json& j, SecretPermanentIdentity const& identity)
{
  j["trustchain_id"] = identity.trustchainId;
  j["target"] = "user";
  j["value"] = identity.delegation.userId;
  j["user_secret"] = identity.userSecret;
  j["ephemeral_public_signature_key"] =
      identity.delegation.ephemeralKeyPair.publicKey;
  j["ephemeral_private_signature_key"] =
      identity.delegation.ephemeralKeyPair.privateKey;
  j["delegation_signature"] = identity.delegation.signature;
}

std::string to_string(SecretPermanentIdentity const& identity)
{
  return cppcodec::base64_rfc4648::encode(nlohmann::json(identity).dump());
}
}
}
