#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>
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

template <typename OutputIterator>
void to_serialized(OutputIterator it, Block const& b)
{
  auto const natureInt = static_cast<unsigned>(b.nature);
  auto const version = 1;

  std::vector<std::uint8_t> buffer(Serialization::serialized_size(b));
  auto bufferIt = buffer.data();
  bufferIt = Serialization::varint_write(bufferIt, version);
  bufferIt = Serialization::varint_write(bufferIt, b.index);
  Serialization::serialize(bufferIt, b.trustchainId);
  bufferIt += Serialization::serialized_size(b.trustchainId);
  bufferIt = Serialization::varint_write(bufferIt, natureInt);
  // payload is a vector<uint8_t>, cannot call serialize with it
  bufferIt = Serialization::varint_write(bufferIt, b.payload.size());
  bufferIt = std::copy(b.payload.begin(), b.payload.end(), bufferIt);
  Serialization::serialize(bufferIt, b.author);
  bufferIt += Serialization::serialized_size(b.author);
  Serialization::serialize(bufferIt, b.signature);
  std::copy(buffer.begin(), buffer.end(), it);
}

std::size_t serialized_size(Block const&);
void from_serialized(Serialization::SerializedSource& ss, Block&);

void to_json(nlohmann::json& j, Block const& b);
}
