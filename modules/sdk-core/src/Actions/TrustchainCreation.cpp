#include <Tanker/Actions/TrustchainCreation.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker
{
Nature TrustchainCreation::nature() const
{
  return Nature::TrustchainCreation;
}

std::vector<Index> TrustchainCreation::makeIndexes() const
{
  return {};
}

bool operator==(TrustchainCreation const& l, TrustchainCreation const& r)
{
  return std::tie(l.publicSignatureKey) == std::tie(r.publicSignatureKey);
}

bool operator!=(TrustchainCreation const& l, TrustchainCreation const& r)
{
  return !(l == r);
}

std::size_t serialized_size(TrustchainCreation const& tc)
{
  return tc.publicSignatureKey.size();
}

void from_serialized(Serialization::SerializedSource& ss,
                     TrustchainCreation& tc)
{
  tc.publicSignatureKey =
      Serialization::deserialize<Crypto::PublicSignatureKey>(ss);
}

void to_json(nlohmann::json& j, TrustchainCreation const& tc)
{
  j["publicSignatureKey"] = tc.publicSignatureKey;
}
}
