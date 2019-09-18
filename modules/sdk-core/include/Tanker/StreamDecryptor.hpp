#pragma once

#include <Tanker/BufferedStream.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/StreamHeader.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace Tanker
{
class StreamDecryptor : BufferedStream<StreamDecryptor>
{
  friend BufferedStream<StreamDecryptor>;

public:
  using ResourceKeyFinder = std::function<tc::cotask<Crypto::SymmetricKey>(
      Trustchain::ResourceId const&)>;

  using BufferedStream<StreamDecryptor>::operator();

  Crypto::SymmetricKey const& symmetricKey() const;
  Trustchain::ResourceId const& resourceId() const;

  static tc::cotask<StreamDecryptor> create(Streams::InputSource,
                                            ResourceKeyFinder);
private:
  explicit StreamDecryptor(Streams::InputSource);

  tc::cotask<void> processInput();
  tc::cotask<void> readHeader();

  tc::cotask<void> decryptChunk();

  Crypto::SymmetricKey _key;
  StreamHeader _header;
  std::int64_t _chunkIndex{};
};
}
