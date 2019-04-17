#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Types/ResourceId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
struct KeyPublishToProvisionalUser
{
  Crypto::PublicSignatureKey appPublicSignatureKey;
  Crypto::PublicSignatureKey tankerPublicSignatureKey;
  ResourceId resourceId;
  Crypto::TwoTimesSealedSymmetricKey key;

  Trustchain::Actions::Nature nature() const;
  std::vector<Index> makeIndexes() const;
};

bool operator==(KeyPublishToProvisionalUser const&,
                KeyPublishToProvisionalUser const&);
bool operator!=(KeyPublishToProvisionalUser const&,
                KeyPublishToProvisionalUser const&);

KeyPublishToProvisionalUser deserializeKeyPublishToProvisionalUser(
    gsl::span<uint8_t const>);

std::uint8_t* to_serialized(std::uint8_t*, KeyPublishToProvisionalUser const&);

constexpr std::size_t serialized_size(KeyPublishToProvisionalUser const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + ResourceId::arraySize +
         Crypto::TwoTimesSealedSymmetricKey::arraySize;
}

void to_json(nlohmann::json& j, KeyPublishToProvisionalUser const& kp);
}
