#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class TrustchainCreation
{
public:
  TrustchainCreation() = default;
  explicit TrustchainCreation(Crypto::PublicSignatureKey const&);

  static constexpr Nature nature();
  Crypto::PublicSignatureKey const& publicSignatureKey() const;

private:
  Crypto::PublicSignatureKey _publicSignatureKey;

  friend void from_serialized(Serialization::SerializedSource&,
                              TrustchainCreation&);
};

bool operator==(TrustchainCreation const& lhs, TrustchainCreation const& rhs);
bool operator!=(TrustchainCreation const& lhs, TrustchainCreation const& rhs);

constexpr Nature TrustchainCreation::nature()
{
  return Nature::TrustchainCreation;
}
}
}
}

#include <Tanker/Trustchain/Json/TrustchainCreation.hpp>
#include <Tanker/Trustchain/Serialization/TrustchainCreation.hpp>
