#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Identity/TargetType.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Identity
{
struct PublicProvisionalIdentity
{
  Trustchain::TrustchainId trustchainId;
  TargetType target;
  std::string value;
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicEncryptionKey appEncryptionPublicKey;
};

void from_json(nlohmann::json const& j, PublicProvisionalIdentity& result);
void to_json(nlohmann::json& j, PublicProvisionalIdentity const& identity);
std::string to_string(PublicProvisionalIdentity const& identity);
}
}
