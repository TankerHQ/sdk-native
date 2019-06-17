#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Unlock
{
struct FetchAnswer
{
  std::vector<uint8_t> encryptedVerificationKey;

  FetchAnswer() = default;
  FetchAnswer(Crypto::SymmetricKey const& key,
              VerificationKey const& verificationKey);

  VerificationKey getVerificationKey(Crypto::SymmetricKey const& key) const;
};
void from_json(nlohmann::json const& j, FetchAnswer& m);

void to_json(nlohmann::json&, FetchAnswer const& m);
}
}
