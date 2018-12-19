#include <Tanker/ChunkEncryptor.hpp>

#include <Tanker/Encryptor.hpp>
#include <Tanker/Session.hpp>

#include <cstdint>
#include <limits>

namespace Tanker
{
ChunkEncryptor::ChunkEncryptor(Session* session) : _session(session)
{
}

tc::cotask<void> ChunkEncryptor::open(gsl::span<uint8_t const> encryptedSeal)
{
  std::vector<uint8_t> decryptedSeal(Encryptor::decryptedSize(encryptedSeal));
  TC_AWAIT(_session->decrypt(decryptedSeal.data(), encryptedSeal));
  _impl.inflate(decryptedSeal);
}

tc::cotask<void> ChunkEncryptor::seal(
    gsl::span<uint8_t> encryptedSeal,
    std::vector<SUserId> const& userIds,
    std::vector<SGroupId> const& groupIds) const
{
  auto const seal = _impl.seal();
  TC_AWAIT(_session->encrypt(encryptedSeal.data(), seal, userIds, groupIds));
}

size_t ChunkEncryptor::sealSize() const
{
  return Encryptor::encryptedSize(_impl.sealSize());
}

size_t ChunkEncryptor::size() const
{
  return _impl.size();
}

void ChunkEncryptor::encrypt(gsl::span<uint8_t> encryptedChunk,
                             gsl::span<uint8_t const> clearChunk,
                             uint64_t index)
{
  if (index == std::numeric_limits<uint64_t>::max())
    index = _impl.size();
  _impl.encrypt(encryptedChunk, clearChunk, index);
}

void ChunkEncryptor::decrypt(gsl::span<uint8_t> decryptedChunk,
                             gsl::span<uint8_t const> encryptedChunk,
                             uint64_t index) const
{
  _impl.decrypt(decryptedChunk, encryptedChunk, index);
}

void ChunkEncryptor::remove(gsl::span<uint64_t const> indexes)
{
  _impl.remove(indexes);
}

uint64_t ChunkEncryptor::encryptedSize(uint64_t clearChunkSize)
{
  return ChunkEncryptorImpl::encryptedSize(clearChunkSize);
}

uint64_t ChunkEncryptor::decryptedSize(gsl::span<uint8_t const> encryptedChunk)
{
  return ChunkEncryptorImpl::decryptedSize(encryptedChunk);
}
}
