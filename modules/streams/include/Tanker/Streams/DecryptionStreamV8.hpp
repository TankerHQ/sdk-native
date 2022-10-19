#pragma once

#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Streams
{
class DecryptionStreamV8 : public DecryptionStream<DecryptionStreamV8>
{
  friend DecryptionStream<DecryptionStreamV8>;

private:
  bool _onlyPaddingLeft = false;

  explicit DecryptionStreamV8(InputSource cb,
                              Header header,
                              Crypto::SymmetricKey key);

  tc::cotask<void> decryptChunk();
  static tc::cotask<std::optional<Crypto::SymmetricKey>> tryGetKey(
      ResourceKeyFinder const& finder, Header const& header);
};
}
