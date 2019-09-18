#pragma once

#include <Tanker/BufferedStream.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace Tanker
{
class StreamEncryptor : BufferedStream<StreamEncryptor>
{
  friend BufferedStream<StreamEncryptor>;

public:
  explicit StreamEncryptor(Streams::InputSource);
  StreamEncryptor(Streams::InputSource, std::uint32_t encryptedChunkSize);

  using BufferedStream<StreamEncryptor>::operator();

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
