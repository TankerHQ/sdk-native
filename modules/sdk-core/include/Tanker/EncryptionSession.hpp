#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_canceler.hpp>

namespace Tanker
{
class Session;

class EncryptionSession
{
public:
  EncryptionSession(std::weak_ptr<Session> tankerSession);

  static constexpr std::uint32_t version()
  {
    return EncryptorV5::version();
  }

  Trustchain::ResourceId const& resourceId() const;
  Crypto::SymmetricKey const& sessionKey() const;
  std::shared_ptr<tc::task_canceler> canceler() const;
  std::uint64_t encryptedSize(std::uint64_t clearSize) const;
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  tc::cotask<EncryptionMetadata> encrypt(
      std::uint8_t* encryptedData, gsl::span<std::uint8_t const> clearData);

private:
  void assertSession(const char* action) const;

  std::weak_ptr<Session> _tankerSession;
  std::shared_ptr<tc::task_canceler> _taskCanceler;
  Crypto::SymmetricKey _sessionKey;
  Trustchain::ResourceId _resourceId;
};
}
