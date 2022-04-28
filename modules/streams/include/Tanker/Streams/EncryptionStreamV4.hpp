#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Streams
{
class EncryptionStreamV4 : public EncryptionStream<EncryptionStreamV4>
{
  friend EncryptionStream<EncryptionStreamV4>;

public:
  inline static constexpr auto overhead =
      Header::serializedSize + Crypto::Mac::arraySize;

  EncryptionStreamV4(
      InputSource,
      std::uint32_t encryptedChunkSize = Header::defaultEncryptedChunkSize);
  EncryptionStreamV4(
      InputSource,
      Trustchain::ResourceId const& resourceId,
      Crypto::SymmetricKey const& key,
      std::uint32_t encryptedChunkSize = Header::defaultEncryptedChunkSize);

private:
  tc::cotask<void> encryptChunk();
};
}
