#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

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

void from_serialized(Serialization::SerializedSource&, TrustchainCreation&);
std::uint8_t* to_serialized(std::uint8_t*, TrustchainCreation const&);

constexpr std::size_t serialized_size(TrustchainCreation const&)
{
  return Crypto::PublicSignatureKey::arraySize;
}

void to_json(nlohmann::json&, TrustchainCreation const&);

constexpr Nature TrustchainCreation::nature()
{
  return Nature::TrustchainCreation;
}
}
}
}
