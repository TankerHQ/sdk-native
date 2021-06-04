#pragma once

#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Utils.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Identity
{

struct SecretPermanentIdentity
{
  Trustchain::TrustchainId trustchainId;
  Delegation delegation;
  Tanker::Crypto::SymmetricKey userSecret;
};

void from_json(nlohmann::json const& j, SecretPermanentIdentity& result);
void to_json(nlohmann::ordered_json& j, SecretPermanentIdentity const& identity);
std::string to_string(SecretPermanentIdentity const& identity);

SecretPermanentIdentity createIdentity(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& trustchainPrivateKey,
    Trustchain::UserId const& userId);

std::string createIdentity(std::string const& trustchainId,
                           std::string const& trustchainPrivateKey,
                           SUserId const& userId);
}
}
