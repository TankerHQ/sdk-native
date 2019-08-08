#include <Tanker/EncryptionFormat/EncryptorV4.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/StreamDecryptor.hpp>
#include <Tanker/StreamEncryptor.hpp>
#include <Tanker/StreamHeader.hpp>

#include <tconcurrent/coroutine.hpp>

#include <algorithm>

using Tanker::Trustchain::ResourceId;

using namespace Tanker::Errors;

namespace Tanker
{
namespace EncryptionFormat
{
namespace EncryptorV4
{
namespace
{
constexpr auto sizeOfChunkSize = sizeof(uint32_t);
auto const versionSize = Serialization::varint_size(version());
auto const headerSize = versionSize + sizeOfChunkSize + ResourceId::arraySize;

// version 4 format layout:
// N * chunk of encryptedChunkSize:
// header: [version, varint] [chunkSize, 4B] [ResourceId, 16B]
// content: [IV seed, 24B] [ciphertext, variable] [MAC, 16B]

uint32_t clearChunkSize(uint32_t const encryptedChunkSize)
{
  return encryptedChunkSize - headerSize - Crypto::AeadIv::arraySize -
         Trustchain::ResourceId::arraySize;
}

auto makeInputReader(gsl::span<std::uint8_t const> buffer)
{
  return
      [index = 0u, buffer](std::uint8_t* out,
                           std::int64_t n) mutable -> tc::cotask<std::int64_t> {
        auto const toRead =
            std::min(n, static_cast<std::int64_t>(buffer.size()) - index);
        std::copy_n(buffer.data() + index, toRead, out);
        index += toRead;
        TC_RETURN(toRead);
      };
}
}

uint64_t encryptedSize(uint64_t clearSize, uint32_t encryptedChunkSize)
{
  auto const chunkSize = clearChunkSize(encryptedChunkSize);
  auto const chunks = clearSize / chunkSize;
  auto const lastClearChunkSize = clearSize % chunkSize;
  return chunks * encryptedChunkSize + headerSize + Crypto::AeadIv::arraySize +
         Crypto::encryptedSize(lastClearChunkSize);
}

uint64_t decryptedSize(gsl::span<uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  auto const header = Serialization::deserialize<StreamHeader>(ss);

  // aead overhead
  if (ss.remaining_size() < Crypto::Mac::arraySize)
    throw formatEx(Errc::InvalidArgument, "truncated encrypted buffer");
  auto const chunks = encryptedData.size() / header.encryptedChunkSize();
  auto const lastClearChunkSize =
      (encryptedData.size() % header.encryptedChunkSize()) -
      Crypto::AeadIv::arraySize - headerSize;
  return chunks * clearChunkSize(header.encryptedChunkSize()) +
         Crypto::decryptedSize(lastClearChunkSize);
}

tc::cotask<EncryptionFormat::EncryptionMetadata> encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    uint32_t encryptedChunkSize)
{
  StreamEncryptor encryptor(makeInputReader(clearData), encryptedChunkSize);

  while (auto const nbRead =
             TC_AWAIT(encryptor(encryptedData, encryptedChunkSize)))
    encryptedData += nbRead;

  TC_RETURN((EncryptionFormat::EncryptionMetadata{encryptor.resourceId(),
                                                  encryptor.symmetricKey()}));
}

tc::cotask<void> decrypt(uint8_t* decryptedData,
                         Crypto::SymmetricKey const& key,
                         gsl::span<uint8_t const> encryptedData)
{
  auto decryptor = TC_AWAIT(StreamDecryptor::create(
      makeInputReader(encryptedData),
      [&key](auto) -> tc::cotask<Crypto::SymmetricKey> { TC_RETURN(key); }));

  while (auto const nbRead = TC_AWAIT(
             decryptor(decryptedData, StreamHeader::defaultEncryptedChunkSize)))
    decryptedData += nbRead;
}

ResourceId extractResourceId(gsl::span<uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  return Serialization::deserialize<StreamHeader>(ss).resourceId();
}
}
}
}
