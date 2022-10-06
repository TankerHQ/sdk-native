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
template <typename Derived>
class DecryptionStream : protected BufferedStream<Derived>
{
  friend BufferedStream<Derived>;

public:
  using ResourceKeyFinder = std::function<tc::cotask<Crypto::SymmetricKey>(
      Crypto::SimpleResourceId const&)>;

  static tc::cotask<Derived> create(InputSource cb, ResourceKeyFinder finder);

  using BufferedStream<Derived>::operator();

  Crypto::SymmetricKey const& symmetricKey() const;
  Crypto::SimpleResourceId const& resourceId() const;

protected:
  Crypto::SymmetricKey _key;
  Header _header;
  std::int64_t _chunkIndex{};

  explicit DecryptionStream(InputSource);

  tc::cotask<void> processInput();
  tc::cotask<void> readHeader();

  void checkHeaderIntegrity(Header const& oldHeader,
                            Header const& currentHeader);
};
}
}

#include <Tanker/Streams/DecryptionStreamImpl.hpp>
