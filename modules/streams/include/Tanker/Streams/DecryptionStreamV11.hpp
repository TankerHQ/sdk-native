#pragma once

#include <Tanker/Encryptor/v11.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Streams/TransparentSessionHeader.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Streams
{
class DecryptionStreamV11
  : public DecryptionStream<DecryptionStreamV11, TransparentSessionHeader>
{
  friend DecryptionStream<DecryptionStreamV11, TransparentSessionHeader>;

private:
  explicit DecryptionStreamV11(InputSource cb,
                               TransparentSessionHeader header,
                               Crypto::SymmetricKey key);

  tc::cotask<void> decryptChunk();
  static tc::cotask<std::optional<Crypto::SymmetricKey>> tryGetKey(
      ResourceKeyFinder const& finder, TransparentSessionHeader const& header);

private:
  std::array<uint8_t, EncryptorV11::macDataSize> _associatedData;
  bool _onlyPaddingLeft;
};
}
