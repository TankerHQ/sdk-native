#pragma once

#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Streams
{
class DecryptionStreamV4 : public DecryptionStream<DecryptionStreamV4>
{
  friend DecryptionStream<DecryptionStreamV4>;

private:
  explicit DecryptionStreamV4(InputSource cb);

  tc::cotask<void> decryptChunk();
};
}
