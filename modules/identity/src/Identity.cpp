#include <Tanker/Identity/Identity.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/Utils.hpp>

#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{

Identity::Identity(UserToken const& userToken, TrustchainId const& trustchainId)
  : UserToken(userToken), trustchainId(trustchainId)
{
}

Identity createIdentity(TrustchainId const& trustchainId,
                        Crypto::PrivateSignatureKey const& trustchainPrivateKey,
                        UserId const& userId)
{
  return Identity(generateUserToken(trustchainPrivateKey, userId),
                  std::move(trustchainId));
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

  auto const trustchainId = base64::decode<TrustchainId>(trustchainIdParam);
  return to_string(createIdentity(
      trustchainId,
      base64::decode<Tanker::Crypto::PrivateSignatureKey>(trustchainPrivateKey),
      Tanker::obfuscateUserId(userId, trustchainId)));
}

Identity upgradeUserToken(TrustchainId const& trustchainId,
                          UserId const& userId,
                          UserToken const& userToken)
{
  if (userToken.delegation.userId != userId)
    throw std::invalid_argument("Wrong userId provided");
  return Identity(std::move(userToken), std::move(trustchainId));
}

std::string upgradeUserToken(std::string const& strustchainId,
                             SUserId const& suserId,
                             std::string const& suserToken)
{
  auto const trustchainId = base64::decode<TrustchainId>(strustchainId);
  auto const userId = Tanker::obfuscateUserId(suserId, trustchainId);
  auto const userToken = extract<UserToken>(suserToken);
  return to_string(upgradeUserToken(trustchainId, userId, userToken));
}

void from_json(nlohmann::json const& j, Identity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "user")
    throw std::invalid_argument("failed to deserialize identity");
  j.at("trustchain_id").get_to(identity.trustchainId);
  j.at("value").get_to(identity.delegation.userId);
  j.at("user_secret").get_to(identity.userSecret);
  j.at("ephemeral_public_signature_key")
      .get_to(identity.delegation.ephemeralKeyPair.publicKey);
  j.at("ephemeral_private_signature_key")
      .get_to(identity.delegation.ephemeralKeyPair.privateKey);
  j.at("delegation_signature").get_to(identity.delegation.signature);
}

void to_json(nlohmann::json& j, Identity const& identity)
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

std::string to_string(Identity const& identity)
{
  return base64::encode(nlohmann::json(identity).dump());
}
}
}
