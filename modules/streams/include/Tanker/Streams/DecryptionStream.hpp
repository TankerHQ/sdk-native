#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Streams/BufferedStream.hpp>
#include <Tanker/Streams/Header.hpp>
#include <Tanker/Streams/InputSource.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Streams
{
template <typename Derived, typename HeaderType>
class DecryptionStream : protected BufferedStream<Derived>
{
  friend BufferedStream<Derived>;

public:
  using ResourceKeyFinder =
      std::function<tc::cotask<std::optional<Crypto::SymmetricKey>>(Crypto::SimpleResourceId const&)>;

  static tc::cotask<Derived> create(InputSource cb, ResourceKeyFinder const& finder);

  using BufferedStream<Derived>::operator();

  Crypto::SymmetricKey const& symmetricKey() const;
  decltype(std::declval<HeaderType>().resourceId()) resourceId() const;

protected:
  Crypto::SymmetricKey _key;
  HeaderType _header;
  std::int64_t _chunkIndex{};

  explicit DecryptionStream(InputSource, HeaderType header, Crypto::SymmetricKey key);

  tc::cotask<void> processInput();
  tc::cotask<HeaderType> readHeader();

  void checkHeaderIntegrity(HeaderType const& oldHeader, HeaderType const& currentHeader);
};
}
}

#include <Tanker/Streams/DecryptionStreamImpl.hpp>
