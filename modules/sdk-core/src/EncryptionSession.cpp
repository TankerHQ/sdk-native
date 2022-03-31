#include <Tanker/EncryptionSession.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>

namespace Tanker
{
EncryptionSession::EncryptionSession(std::weak_ptr<Session> tankerSession)
  : _tankerSession(tankerSession),
    _taskCanceler{std::make_shared<tc::task_canceler>()},
    _sessionKey{Crypto::makeSymmetricKey()},
    _resourceId{Crypto::getRandom<Trustchain::ResourceId>()}
{
}

void EncryptionSession::assertSession(char const* action) const
{
  if (_tankerSession.expired())
    throw Errors::formatEx(
        Errors::Errc::PreconditionFailed,
        FMT_STRING("can't call EncryptionSession::{:s} after the Tanker "
                   "session has been closed"),
        action);
}

Trustchain::ResourceId const& EncryptionSession::resourceId() const
{
  assertSession("resourceId");
  return _resourceId;
}

Crypto::SymmetricKey const& EncryptionSession::sessionKey() const
{
  assertSession("sessionKey");
  return _sessionKey;
}

std::shared_ptr<tc::task_canceler> EncryptionSession::canceler() const
{
  return _taskCanceler;
}

std::uint64_t EncryptionSession::encryptedSize(std::uint64_t clearSize)
{
  if (Encryptor::isHugeClearData(clearSize))
    return EncryptorV4::encryptedSize(clearSize);
  else
    return EncryptorV5::encryptedSize(clearSize);
}

tconcurrent::cotask<Tanker::EncryptionMetadata> EncryptionSession::encrypt(
    gsl::span<std::uint8_t> encryptedData,
    gsl::span<const std::uint8_t> clearData)
{
  assertSession("encrypt");
  if (Encryptor::isHugeClearData(clearData.size()))
    TC_RETURN(TC_AWAIT(EncryptorV4::encrypt(
        encryptedData, clearData, _resourceId, _sessionKey)));
  else
    TC_RETURN(TC_AWAIT(EncryptorV5::encrypt(
        encryptedData, clearData, _resourceId, _sessionKey)));
}

std::tuple<Streams::InputSource, Trustchain::ResourceId>
EncryptionSession::makeEncryptionStream(Streams::InputSource cb)
{
  return std::make_tuple(
      Streams::EncryptionStream(std::move(cb), _resourceId, _sessionKey),
      _resourceId);
}
}
