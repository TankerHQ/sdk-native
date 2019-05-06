#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
TrustchainCreation::TrustchainCreation(
    Crypto::PublicSignatureKey const& publicSignatureKey)
  : _publicSignatureKey(publicSignatureKey)
{
}

Crypto::PublicSignatureKey const& TrustchainCreation::publicSignatureKey() const
{
  return _publicSignatureKey; 
}

bool operator==(TrustchainCreation const& lhs, TrustchainCreation const& rhs)
{
  return lhs.publicSignatureKey() == rhs.publicSignatureKey();
}

bool operator!=(TrustchainCreation const& lhs, TrustchainCreation const& rhs)
{
  return !(lhs == rhs);
}

void from_serialized(Serialization::SerializedSource& ss,
                     TrustchainCreation& tc)
{
  Serialization::deserialize_to(ss, tc._publicSignatureKey);
}

std::uint8_t* to_serialized(std::uint8_t* it, TrustchainCreation const& tc)
{
  return Serialization::serialize(it, tc.publicSignatureKey());
}

void to_json(nlohmann::json& j, TrustchainCreation const& tc)
{
  j["publicSignatureKey"] = tc.publicSignatureKey();
}
}
}
}
