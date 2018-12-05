#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json_fwd.hpp>

#include <vector>

namespace Tanker
{
struct TrustchainCreation
{
  Crypto::PublicSignatureKey publicSignatureKey;

  Nature nature() const;
  std::vector<Index> makeIndexes() const;
};

bool operator==(TrustchainCreation const& l, TrustchainCreation const& r);
bool operator!=(TrustchainCreation const& l, TrustchainCreation const& r);

void to_json(nlohmann::json& j, TrustchainCreation const& tc);

template <typename OutputIterator>
void to_serialized(OutputIterator it, TrustchainCreation const& tc)
{
  Serialization::serialize(it, tc.publicSignatureKey);
}

std::size_t serialized_size(TrustchainCreation const&);
void from_serialized(Serialization::SerializedSource& ss,
                     TrustchainCreation& tc);
}
