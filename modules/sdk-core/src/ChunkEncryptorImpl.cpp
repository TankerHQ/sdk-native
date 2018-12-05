#include <Tanker/ChunkEncryptorImpl.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Seal.hpp>

#include <fmt/format.h>
#include <optional.hpp>

#include <vector>

namespace Tanker
{

void ChunkEncryptorImpl::inflate(gsl::span<uint8_t const> seal)
{
  _seal = Seal::inflate(seal);
  if (_seal.version() != Seal::defaultSealVersion())
    throw Error::formatEx<Error::VersionNotSupported>(
        fmt("version '{:d}' of the seal not supported"), _seal.version());
}

size_t ChunkEncryptorImpl::size() const
{
  return _seal.nbElements();
}

void ChunkEncryptorImpl::encrypt(gsl::span<uint8_t> encryptedChunk,
                                 gsl::span<uint8_t const> clearChunk,
                                 uint64_t index)
{
  auto const key = Crypto::makeSymmetricKey();
  auto const iv =
      encryptedChunk.data() + encryptedChunk.size() - Crypto::AeadIv::arraySize;
  Crypto::randomFill(gsl::span<uint8_t>(iv, Crypto::AeadIv::arraySize));
  Crypto::encryptAead(key, iv, encryptedChunk.data(), clearChunk, {});

  _seal.addChunkAt(key, index);
}

void ChunkEncryptorImpl::decrypt(gsl::span<uint8_t> decryptedChunk,
                                 gsl::span<uint8_t const> encryptedChunk,
                                 uint64_t index) const
{
  if (index >= size())
    throw Error::formatEx<Error::ChunkIndexOutOfRange>(
        fmt("index '{:d}' is out of range. chunk count : '{:d}'"),
        index,
        size());
  auto const key = _seal.chunkAt(index);
  if (!key)
    throw Error::formatEx<Error::ChunkNotFound>(
        fmt("chunk pointed by index '{:d}' is empty"), index);

  auto const iv =
      encryptedChunk.data() + encryptedChunk.size() - Crypto::AeadIv::arraySize;
  auto const cipherText = encryptedChunk.subspan(
      0, encryptedChunk.size() - Crypto::AeadIv::arraySize);
  Crypto::decryptAead(*key, iv, decryptedChunk.data(), cipherText, {});
}

void ChunkEncryptorImpl::remove(gsl::span<uint64_t const> idxs)
{
  return _seal.remove(idxs);
}

uint64_t ChunkEncryptorImpl::encryptedSize(uint64_t clearChunkSize)
{
  return Crypto::AeadIv::arraySize + Crypto::encryptedSize(clearChunkSize);
}

uint64_t ChunkEncryptorImpl::decryptedSize(
    gsl::span<uint8_t const> encryptedChunk)
{
  return Crypto::decryptedSize(encryptedChunk.size() -
                               Crypto::AeadIv::arraySize);
}

size_t ChunkEncryptorImpl::sealSize() const
{
  return _seal.size();
}

std::vector<uint8_t> ChunkEncryptorImpl::seal() const
{
  return _seal.serialize();
}
}
