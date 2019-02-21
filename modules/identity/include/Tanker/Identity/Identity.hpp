#pragma once

#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Identity
{

enum class TargetType
{
  None = 0,
  Email = 1,
};

struct PreshareKeys
{
  Crypto::EncryptionKeyPair encryptionKeys;
  Crypto::SignatureKeyPair signatureKeys;
};

struct Identity : public UserToken
{
  TrustchainId trustchainId;
  Identity() = default;
  Identity(UserToken const& userToken, TrustchainId const& trustchainId);
};

void from_json(nlohmann::json const& j, Identity& result);
void to_json(nlohmann::json& j, Identity const& identity);
std::string to_string(Identity const& identity);

template <>
Identity from_string(std::string const&);

Identity createIdentity(TrustchainId const& trustchainId,
                        Crypto::PrivateSignatureKey const& trustchainPrivateKey,
                        UserId const& userId);

std::string createIdentity(std::string const& trustchainId,
                           std::string const& trustchainPrivateKey,
                           SUserId const& userId);

Identity upgradeUserToken(TrustchainId const& trustchainId,
                          UserToken const& userToken);

std::string upgradeUserToken(std::string const& trustchainId,
                             std::string const& userToken);
}
}
