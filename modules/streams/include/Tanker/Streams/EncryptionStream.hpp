#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Streams/BufferedStream.hpp>
#include <Tanker/Streams/Header.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Streams
{
template <typename Derived>
class EncryptionStream : protected BufferedStream<Derived>
{
  friend BufferedStream<Derived>;

public:
  using BufferedStream<Derived>::operator();

  Trustchain::ResourceId const& resourceId() const;
  Crypto::SymmetricKey const& symmetricKey() const;

protected:
  EncryptionStream(InputSource,
                   Trustchain::ResourceId const& resourceId,
                   Crypto::SymmetricKey const& key,
                   std::uint32_t encryptedChunkSize);

  tc::cotask<void> processInput();

  std::int32_t _encryptedChunkSize;
  Trustchain::ResourceId _resourceId;
  Crypto::SymmetricKey _key;
  std::int64_t _chunkIndex{};
};
}
}

#include <Tanker/Streams/EncryptionStreamImpl.hpp>
