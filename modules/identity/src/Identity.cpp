#include <Tanker/Identity/Identity.hpp>

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
                          UserToken const& userToken)
{
  return Identity(std::move(userToken), std::move(trustchainId));
}

std::string upgradeUserToken(std::string const& trustchainId,
                             std::string const& userToken)
{
  return to_string(upgradeUserToken(base64::decode<TrustchainId>(trustchainId),
                                    extract(userToken)));
}

void from_json(nlohmann::json const& j, Identity& identity)
{
  j.at("trustchain_id").get_to(identity.trustchainId);
  j.at("user_id").get_to(identity.delegation.userId);
  j.at("user_secret").get_to(identity.userSecret);
  j.at("delegation")
      .at("ephemeral_signature_public_key")
      .get_to(identity.delegation.ephemeralKeyPair.publicKey);
  j.at("delegation")
      .at("ephemeral_signature_private_key")
      .get_to(identity.delegation.ephemeralKeyPair.privateKey);
  j.at("delegation")
      .at("ephemeral_signature")
      .get_to(identity.delegation.signature);
}

void to_json(nlohmann::json& j, Identity const& identity)
{
  j["trustchain_id"] = identity.trustchainId;
  j["user_id"] = identity.delegation.userId;
  j["user_secret"] = identity.userSecret;
  j["delegation"] = {
      {"ephemeral_signature_public_key",
       identity.delegation.ephemeralKeyPair.publicKey},
      {"ephemeral_signature_private_key",
       identity.delegation.ephemeralKeyPair.privateKey},
      {"ephemeral_signature", identity.delegation.signature},
  };
}

std::string to_string(Identity const& identity)
{
  return base64::encode(nlohmann::json(identity).dump());
}

template <>
Identity from_string(std::string const& s)
{
  return nlohmann::json::parse(base64::decode(s)).get<Identity>();
}
}
}
