#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/task_canceler.hpp>
#include <tconcurrent/stackful_coroutine.hpp>

namespace Tanker
{
class EncryptionSession
{
public:
  EncryptionSession();

  static constexpr std::uint32_t version()
  {
    return EncryptorV5::version();
  }

  Trustchain::ResourceId const& resourceId() const;
  Crypto::SymmetricKey const& sessionKey() const;
  std::shared_ptr<task_canceler> canceler() const;
  static std::uint64_t encryptedSize(std::uint64_t clearSize);
  static std::uint64_t decryptedSize(
      gsl::span<std::uint8_t const> encryptedData);
  tc::cotask<EncryptionMetadata> encrypt(
      std::uint8_t* encryptedData, gsl::span<std::uint8_t const> clearData);

private:
  std::shared_ptr<task_canceler> _taskCanceler;
  Crypto::SymmetricKey _sessionKey;
  Trustchain::ResourceId _resourceId;
};
}
