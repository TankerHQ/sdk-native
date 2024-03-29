#pragma once

#include <Tanker/Crypto/AeadIv.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Streams
{
class Header
{
public:
  static constexpr auto versions = {4u, 8u};
  static constexpr std::uint32_t versionSize = 1u;
  static constexpr std::uint32_t defaultEncryptedChunkSize = 1024 * 1024;
  static constexpr std::uint32_t serializedSize =
      versionSize + sizeof(std::uint32_t) + Crypto::SimpleResourceId::arraySize + Crypto::AeadIv::arraySize;

  Header() = default;
  Header(std::uint32_t version,
         std::uint32_t encryptedChunkSize,
         Crypto::SimpleResourceId const& resourceId,
         Crypto::AeadIv const& seed);

  std::uint32_t version() const;
  std::uint32_t encryptedChunkSize() const;
  Crypto::SimpleResourceId const& resourceId() const;
  Crypto::AeadIv const& seed() const;

private:
  friend void from_serialized(Serialization::SerializedSource&, Header&);

  std::uint32_t _version;
  std::uint32_t _encryptedChunkSize;
  Crypto::SimpleResourceId _resourceId;
  Crypto::AeadIv _seed;
};

void from_serialized(Serialization::SerializedSource&, Header&);
std::uint8_t* to_serialized(std::uint8_t*, Header const&);

constexpr std::size_t serialized_size(Header const&)
{
  return Header::serializedSize;
}
}
}
