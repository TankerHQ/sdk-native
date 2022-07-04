#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker::Streams
{
class EncryptionStreamV8 : public EncryptionStream<EncryptionStreamV8>
{
  friend EncryptionStream<EncryptionStreamV8>;

public:
  inline static constexpr auto overhead =
      Header::serializedSize + Crypto::Mac::arraySize + 1;

  EncryptionStreamV8(
      InputSource,
      std::optional<std::uint32_t> padding = std::nullopt,
      std::uint32_t encryptedChunkSize = Header::defaultEncryptedChunkSize);
  EncryptionStreamV8(
      InputSource,
      Trustchain::ResourceId const& resourceId,
      Crypto::SymmetricKey const& key,
      std::optional<std::uint32_t> padding = std::nullopt,
      std::uint32_t encryptedChunkSize = Header::defaultEncryptedChunkSize);

private:
  std::optional<std::uint32_t> _paddingStep;
  std::optional<std::uint64_t> _paddingLeftToAdd;

  tc::cotask<void> encryptChunk();
};
}
