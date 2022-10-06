#pragma once

#include <Tanker/Crypto/CompositeResourceId.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Streams/BufferedStream.hpp>
#include <Tanker/Streams/Header.hpp>
#include <Tanker/Streams/InputSource.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Streams
{
template <typename Derived, typename ResourceIdType = Crypto::SimpleResourceId>
class EncryptionStream : protected BufferedStream<Derived>
{
  friend BufferedStream<Derived>;

public:
  using BufferedStream<Derived>::operator();

  ResourceIdType const& resourceId() const;
  Crypto::SymmetricKey const& symmetricKey() const;

protected:
  EncryptionStream(InputSource,
                   ResourceIdType const& resourceId,
                   Crypto::SymmetricKey const& key,
                   std::uint32_t encryptedChunkSize);

  tc::cotask<void> processInput();

  std::int32_t _encryptedChunkSize;
  ResourceIdType _resourceId;
  Crypto::SymmetricKey _key;
  std::int64_t _chunkIndex{};
};
}
}

#include <Tanker/Streams/EncryptionStreamImpl.hpp>
