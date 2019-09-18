#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Streams/BufferedStream.hpp>
#include <Tanker/Streams/Header.hpp>
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
namespace Streams
{
class DecryptionStream : BufferedStream<DecryptionStream>
{
  friend BufferedStream<DecryptionStream>;

public:
  using ResourceKeyFinder = std::function<tc::cotask<Crypto::SymmetricKey>(
      Trustchain::ResourceId const&)>;

  using BufferedStream<DecryptionStream>::operator();

  Crypto::SymmetricKey const& symmetricKey() const;
  Trustchain::ResourceId const& resourceId() const;

  static tc::cotask<DecryptionStream> create(InputSource, ResourceKeyFinder);

private:
  explicit DecryptionStream(InputSource);

  tc::cotask<void> processInput();
  tc::cotask<void> readHeader();

  tc::cotask<void> decryptChunk();

  Crypto::SymmetricKey _key;
  Header _header;
  std::int64_t _chunkIndex{};
};
}
}
