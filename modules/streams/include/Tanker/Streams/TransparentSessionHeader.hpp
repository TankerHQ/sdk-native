#pragma once

#include <Tanker/Crypto/CompositeResourceId.hpp>
#include <Tanker/Crypto/SubkeySeed.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker::Streams
{
class TransparentSessionHeader
{
public:
  static constexpr auto versions = {11u, 12u};
  static constexpr std::uint32_t versionSize = 1u;
  static constexpr std::uint32_t defaultEncryptedChunkSize = 1024 * 1024;
  static constexpr std::uint32_t serializedSize =
      versionSize + Crypto::SimpleResourceId::arraySize +
      Crypto::SubkeySeed::arraySize + sizeof(std::uint32_t);

  TransparentSessionHeader() = default;
  TransparentSessionHeader(std::uint32_t version,
                           std::uint32_t encryptedChunkSize,
                           Crypto::CompositeResourceId const& resourceId);

  std::uint32_t version() const;
  std::uint32_t encryptedChunkSize() const;
  Crypto::CompositeResourceId const& resourceId() const;

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              TransparentSessionHeader&);

  std::uint32_t _version;
  std::uint32_t _encryptedChunkSize;
  Crypto::CompositeResourceId _resourceId;
};

void from_serialized(Serialization::SerializedSource&,
                     TransparentSessionHeader&);
std::uint8_t* to_serialized(std::uint8_t*, TransparentSessionHeader const&);

constexpr std::size_t serialized_size(TransparentSessionHeader const&)
{
  return TransparentSessionHeader::serializedSize;
}
}
