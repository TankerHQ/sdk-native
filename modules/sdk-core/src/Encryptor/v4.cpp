#include <Tanker/Encryptor/v4.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/Header.hpp>
#include <Tanker/Streams/Helpers.hpp>

#include <tconcurrent/coroutine.hpp>

#include <algorithm>

using Tanker::Trustchain::ResourceId;

using namespace Tanker::Errors;
using namespace Tanker::Streams;

namespace Tanker
{
namespace
{
constexpr auto sizeOfChunkSize = sizeof(std::uint32_t);
auto const versionSize = Serialization::varint_size(EncryptorV4::version());
auto const headerSize = versionSize + sizeOfChunkSize + ResourceId::arraySize;

// version 4 format layout:
// N * chunk of encryptedChunkSize:
// header: [version, varint] [chunkSize, 4B] [ResourceId, 16B]
// content: [IV seed, 24B] [ciphertext, variable] [MAC, 16B]

constexpr std::uint32_t clearChunkSize(std::uint32_t encryptedChunkSize)
{
  return encryptedChunkSize - headerSize - Crypto::AeadIv::arraySize -
         Trustchain::ResourceId::arraySize;
}
}

std::uint64_t EncryptorV4::encryptedSize(std::uint64_t clearSize,
                                         std::uint32_t encryptedChunkSize)
{
  auto const chunkSize = clearChunkSize(encryptedChunkSize);
  auto const chunks = clearSize / chunkSize;
  auto const lastClearChunkSize = clearSize % chunkSize;
  return chunks * encryptedChunkSize + headerSize + Crypto::AeadIv::arraySize +
         Crypto::encryptedSize(lastClearChunkSize);
}

std::uint64_t EncryptorV4::decryptedSize(
    gsl::span<std::uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  auto const header = Serialization::deserialize<Header>(ss);

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

tc::cotask<EncryptionMetadata> EncryptorV4::encrypt(
    std::uint8_t* encryptedData,
    gsl::span<std::uint8_t const> clearData,
    std::uint32_t encryptedChunkSize)
{
  EncryptionStream encryptor(bufferViewToInputSource(clearData),
                            encryptedChunkSize);

  while (auto const nbRead =
             TC_AWAIT(encryptor(encryptedData, encryptedChunkSize)))
    encryptedData += nbRead;

  TC_RETURN(
      (EncryptionMetadata{encryptor.resourceId(), encryptor.symmetricKey()}));
}

tc::cotask<void> EncryptorV4::decrypt(
    std::uint8_t* decryptedData,
    Crypto::SymmetricKey const& key,
    gsl::span<std::uint8_t const> encryptedData)
{
  auto decryptor = TC_AWAIT(DecryptionStream::create(
      bufferViewToInputSource(encryptedData),
      [&key](auto) -> tc::cotask<Crypto::SymmetricKey> { TC_RETURN(key); }));

  while (auto const nbRead = TC_AWAIT(
             decryptor(decryptedData, Header::defaultEncryptedChunkSize)))
    decryptedData += nbRead;
}

ResourceId EncryptorV4::extractResourceId(
    gsl::span<std::uint8_t const> encryptedData)
{
  Serialization::SerializedSource ss{encryptedData};
  return Serialization::deserialize<Header>(ss).resourceId();
}
}
