#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Streams/BufferedStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Streams
{
class EncryptionStream : BufferedStream<EncryptionStream>
{
  friend BufferedStream<EncryptionStream>;

public:
  explicit EncryptionStream(InputSource);
  EncryptionStream(InputSource, std::uint32_t encryptedChunkSize);
  EncryptionStream(InputSource,
                   Trustchain::ResourceId const& resourceId,
                   Crypto::SymmetricKey const& key);

  using BufferedStream<EncryptionStream>::operator();

  Trustchain::ResourceId const& resourceId() const;
  Crypto::SymmetricKey const& symmetricKey() const;

private:
  tc::cotask<void> encryptChunk();

  tc::cotask<void> processInput();

  std::int32_t _encryptedChunkSize;
  Trustchain::ResourceId _resourceId;
  Crypto::SymmetricKey _key;
  std::int64_t _chunkIndex{};
};
}
}
