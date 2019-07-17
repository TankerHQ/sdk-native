#pragma once

#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
class StreamHeader
{
public:
  static constexpr std::uint32_t currentVersion = 4u;
  static constexpr std::uint32_t serializedSize =
      Serialization::varint_size(StreamHeader::currentVersion) +
      sizeof(std::uint32_t) + Trustchain::ResourceId::arraySize +
      Crypto::AeadIv::arraySize;

  StreamHeader() = default;
  StreamHeader(std::uint32_t encryptedChunkSize,
               Trustchain::ResourceId const& resourceId,
               Crypto::AeadIv const& seed);

  std::uint32_t version() const;
  std::uint32_t encryptedChunkSize() const;
  Trustchain::ResourceId const& resourceId() const;
  Crypto::AeadIv const& seed() const;

private:
  friend void from_serialized(Serialization::SerializedSource&, StreamHeader&);

  std::uint32_t _version;
  std::uint32_t _encryptedChunkSize;
  Trustchain::ResourceId _resourceId;
  Crypto::AeadIv _seed;
};

void from_serialized(Serialization::SerializedSource&, StreamHeader&);
std::uint8_t* to_serialized(std::uint8_t*, StreamHeader const&);

constexpr std::size_t serialized_size(StreamHeader const&) 
{
  return StreamHeader::serializedSize;
}
}
