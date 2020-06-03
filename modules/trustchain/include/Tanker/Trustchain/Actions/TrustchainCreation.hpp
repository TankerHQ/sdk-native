#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_TRUSTCHAIN_CREATION_ATTRIBUTES \
  (publicSignatureKey, Crypto::PublicSignatureKey)

class TrustchainCreation
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      TrustchainCreation,
      TANKER_TRUSTCHAIN_ACTIONS_TRUSTCHAIN_CREATION_ATTRIBUTES)

public:
  explicit TrustchainCreation(Crypto::PublicSignatureKey const&);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              TrustchainCreation&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(TrustchainCreation)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(TrustchainCreation)
}
}
}
