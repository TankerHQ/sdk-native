#include <Tanker/EncryptionSession.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Encryptor/v5.hpp>

namespace Tanker
{
EncryptionSession::EncryptionSession()
  : _taskCanceler{std::make_shared<task_canceler>()},
    _sessionKey{Crypto::makeSymmetricKey()},
    _resourceId{Crypto::getRandom<Trustchain::ResourceId>()}
{
}

Trustchain::ResourceId const& EncryptionSession::resourceId() const
{
  return _resourceId;
}

Crypto::SymmetricKey const& EncryptionSession::sessionKey() const
{
  return _sessionKey;
}

std::shared_ptr<task_canceler> EncryptionSession::canceler() const
{
  return _taskCanceler;
}

std::uint64_t EncryptionSession::encryptedSize(std::uint64_t clearSize)
{
  return EncryptorV5::encryptedSize(clearSize);
}

std::uint64_t EncryptionSession::decryptedSize(
    gsl::span<const std::uint8_t> encryptedData)
{
  return EncryptorV5::decryptedSize(encryptedData);
}

tconcurrent::cotask<Tanker::EncryptionMetadata> EncryptionSession::encrypt(
    std::uint8_t* encryptedData, gsl::span<const std::uint8_t> clearData)
{
  TC_RETURN(TC_AWAIT(EncryptorV5::encrypt(
      encryptedData, clearData, _resourceId, _sessionKey)));
}
}
