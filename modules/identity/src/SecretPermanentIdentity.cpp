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

SecretPermanentIdentity createIdentity(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& trustchainPrivateKey,
    Trustchain::UserId const& userId)
{
  return SecretPermanentIdentity{
      trustchainId,
      makeDelegation(userId, trustchainPrivateKey),
      generateUserSecret(userId),
  };
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

void from_json(nlohmann::json const& j, SecretPermanentIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target != "user")
  {
    if (target == "email")
      throw Errors::formatEx(Errc::InvalidFormat,
                             "invalid identity (expected a permanent identity, "
                             "got a provisional identity)");
    else
      throw Errors::formatEx(Errc::InvalidPermanentIdentityTarget,
                             "unsupported identity target: {}",
                             target);
  }
  j.at("trustchain_id").get_to(identity.trustchainId);
  j.at("value").get_to(identity.delegation.userId);

  if (j.find("user_secret") == j.end())
  {
    throw Errors::formatEx(
        Errc::InvalidFormat,
        "invalid identity (expected an identity, got a public identity)");
  }

  j.at("user_secret").get_to(identity.userSecret);
  j.at("ephemeral_public_signature_key")
      .get_to(identity.delegation.ephemeralKeyPair.publicKey);
  j.at("ephemeral_private_signature_key")
      .get_to(identity.delegation.ephemeralKeyPair.privateKey);
  j.at("delegation_signature").get_to(identity.delegation.signature);
}

void to_json(nlohmann::ordered_json& j, SecretPermanentIdentity const& identity)
{
  j["trustchain_id"] = identity.trustchainId;
  j["target"] = "user";
  j["value"] = identity.delegation.userId;
  j["delegation_signature"] = identity.delegation.signature;
  j["ephemeral_public_signature_key"] =
      identity.delegation.ephemeralKeyPair.publicKey;
  j["ephemeral_private_signature_key"] =
      identity.delegation.ephemeralKeyPair.privateKey;
  j["user_secret"] = identity.userSecret;
}

std::string to_string(SecretPermanentIdentity const& identity)
{
  return mgs::base64::encode(nlohmann::ordered_json(identity).dump());
}
}
}
