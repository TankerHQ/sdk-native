#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_TRUSTCHAIN_CREATION_ATTRIBUTES (publicSignatureKey, Crypto::PublicSignatureKey)

class TrustchainCreation
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(TrustchainCreation, TANKER_TRUSTCHAIN_ACTIONS_TRUSTCHAIN_CREATION_ATTRIBUTES)

public:
  explicit TrustchainCreation(Crypto::PublicSignatureKey const&);

private:
  friend void from_serialized(Serialization::SerializedSource&, TrustchainCreation&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(TrustchainCreation)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(TrustchainCreation)
}
}
}
