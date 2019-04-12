#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{
struct Block
{
  TrustchainId trustchainId;
  uint64_t index;
  Crypto::Hash author;
  Nature nature;
  std::vector<uint8_t> payload;
  Crypto::Signature signature;

  Crypto::Hash hash() const;
  bool verifySignature(
      Crypto::PublicSignatureKey const& publicSignatureKey) const;
};

bool operator==(Block const& l, Block const& r);
bool operator!=(Block const& l, Block const& r);

std::size_t serialized_size(Block const&);
void from_serialized(Serialization::SerializedSource& ss, Block&);
std::uint8_t* to_serialized(std::uint8_t* it, Block const& b);

void to_json(nlohmann::json& j, Block const& b);
}
