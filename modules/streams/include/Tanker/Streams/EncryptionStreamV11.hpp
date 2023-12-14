#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SubkeySeed.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Encryptor/v11.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Streams/TransparentSessionHeader.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Streams
{
class EncryptionStreamV11 : public EncryptionStream<EncryptionStreamV11, Crypto::CompositeResourceId>
{
  friend EncryptionStream<EncryptionStreamV11, Crypto::CompositeResourceId>;

public:
  inline static constexpr auto overhead = EncryptorV11::paddingSizeSize + Crypto::Mac::arraySize;

  EncryptionStreamV11(InputSource,
                      Crypto::SimpleResourceId const& sessionId,
                      Crypto::SymmetricKey const& sessionKey,
                      std::optional<std::uint32_t> padding,
                      std::uint32_t encryptedChunkSize = TransparentSessionHeader::defaultEncryptedChunkSize);
  EncryptionStreamV11(InputSource,
                      Crypto::SimpleResourceId const& sessionId,
                      Crypto::SymmetricKey const& sessionKey,
                      Crypto::SubkeySeed const& subkeySeed,
                      std::optional<std::uint32_t> padding,
                      std::uint32_t encryptedChunkSize = TransparentSessionHeader::defaultEncryptedChunkSize);

private:
  tc::cotask<void> encryptChunk();
  tc::cotask<void> writeHeader();

  std::array<uint8_t, EncryptorV11::macDataSize> _associatedData;
  Crypto::SymmetricKey _subkey;
  std::optional<std::uint32_t> _paddingStep;
  std::optional<std::uint64_t> _paddingLeftToAdd;
  bool _wroteHeader;
};
}
