#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/EncryptionMetadata.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <optional>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_canceler.hpp>

namespace Tanker
{
class Session;

class EncryptionSession
{
public:
  EncryptionSession(std::weak_ptr<Session> tankerSession,
                    std::optional<std::uint32_t> paddingStep = std::nullopt);
  Trustchain::ResourceId const& resourceId() const;
  Crypto::SymmetricKey const& sessionKey() const;
  std::shared_ptr<tc::task_canceler> canceler() const;
  std::uint64_t encryptedSize(std::uint64_t clearSize) const;
  tc::cotask<EncryptionMetadata> encrypt(
      gsl::span<std::uint8_t> encryptedData,
      gsl::span<std::uint8_t const> clearData);
  std::tuple<Streams::InputSource, Trustchain::ResourceId> makeEncryptionStream(
      Streams::InputSource cb);

private:
  void assertSession(const char* action) const;

  std::weak_ptr<Session> _tankerSession;
  std::shared_ptr<tc::task_canceler> _taskCanceler;
  Crypto::SymmetricKey _sessionKey;
  Trustchain::ResourceId _resourceId;
  std::optional<std::uint32_t> _paddingStep;
};
}
