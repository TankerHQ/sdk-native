#pragma once

#include <Tanker/Identity/TargetType.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/Email.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Identity
{
struct SecretProvisionalIdentity
{
  Trustchain::TrustchainId trustchainId;
  TargetType target;
  std::string value;
  Crypto::SignatureKeyPair appSignatureKeyPair;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
};

void from_json(nlohmann::json const& j, SecretProvisionalIdentity& result);
void to_json(nlohmann::json& j, SecretProvisionalIdentity const& identity);
std::string to_string(SecretProvisionalIdentity const& identity);

SecretProvisionalIdentity createProvisionalIdentity(
    Trustchain::TrustchainId const& trustchainId, Email const& email);

std::string createProvisionalIdentity(std::string const& trustchainId,
                                      Email const& email);
}
}
