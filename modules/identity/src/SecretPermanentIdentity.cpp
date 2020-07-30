#include <Tanker/Identity/SecretPermanentIdentity.hpp>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/Utils.hpp>

#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <mgs/base64.hpp>

namespace Tanker
{
namespace Identity
{

SecretPermanentIdentity::SecretPermanentIdentity(
    UserToken const& userToken, Trustchain::TrustchainId const& trustchainId)
  : UserToken(userToken), trustchainId(trustchainId)
{
}

SecretPermanentIdentity createIdentity(
    Trustchain::TrustchainId const& trustchainId,
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
    throw Errors::Exception(Errc::InvalidUserId);
  if (trustchainIdParam.empty())
    throw Errors::Exception(Errc::InvalidTrustchainId);
  if (trustchainPrivateKey.empty())
    throw Errors::Exception(Errc::InvalidTrustchainPrivateKey);

  auto const trustchainId =
      mgs::base64::decode<Trustchain::TrustchainId>(trustchainIdParam);
  return to_string(
      createIdentity(trustchainId,
                     mgs::base64::decode<Tanker::Crypto::PrivateSignatureKey>(
                         trustchainPrivateKey),
                     Tanker::obfuscateUserId(userId, trustchainId)));
}

SecretPermanentIdentity upgradeUserToken(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    UserToken const& userToken)
{
  if (userToken.delegation.userId != userId)
    throw Errors::Exception(Errc::InvalidUserId, "invalid user id provided");
  return SecretPermanentIdentity(std::move(userToken), std::move(trustchainId));
}

std::string upgradeUserToken(std::string const& strustchainId,
                             SUserId const& suserId,
                             std::string const& suserToken)
{
  auto const trustchainId =
      mgs::base64::decode<Trustchain::TrustchainId>(strustchainId);
  auto const userId = Tanker::obfuscateUserId(suserId, trustchainId);
  auto const userToken = extract<UserToken>(suserToken);
  return to_string(upgradeUserToken(trustchainId, userId, userToken));
}

void from_json(nlohmann::json const& j, SecretPermanentIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "user")
  {
    throw Errors::formatEx(Errc::InvalidPermanentIdentityTarget,
                           "unsupported provisional identity target: {}",
                           target);
  }
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
  return mgs::base64::encode(nlohmann::json(identity).dump());
}
}
}
