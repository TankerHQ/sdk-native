#pragma once

#include <Tanker/Identity/UserToken.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/UserId.hpp>
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

struct SecretPermanentIdentity : public UserToken
{
  TrustchainId trustchainId;
  SecretPermanentIdentity() = default;
  SecretPermanentIdentity(UserToken const& userToken,
                          TrustchainId const& trustchainId);
};

void from_json(nlohmann::json const& j, SecretPermanentIdentity& result);
void to_json(nlohmann::json& j, SecretPermanentIdentity const& identity);
std::string to_string(SecretPermanentIdentity const& identity);

SecretPermanentIdentity createIdentity(
    TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& trustchainPrivateKey,
    Trustchain::UserId const& userId);

std::string createIdentity(std::string const& trustchainId,
                           std::string const& trustchainPrivateKey,
                           SUserId const& userId);

SecretPermanentIdentity upgradeUserToken(TrustchainId const& trustchainId,
                                         Trustchain::UserId const& userId,
                                         UserToken const& userToken);

std::string upgradeUserToken(std::string const& trustchainId,
                             SUserId const& suserId,
                             std::string const& userToken);
}
}
