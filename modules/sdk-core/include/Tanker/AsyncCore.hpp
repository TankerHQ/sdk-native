#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/Core.hpp>
#include <Tanker/Log/LogHandler.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Streams/DecryptionStreamAdapter.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/SDeviceId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <tconcurrent/future.hpp>
#include <tconcurrent/lazy/task_canceler.hpp>
#include <tconcurrent/semaphore.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
// You don't have to wait for these,
// result will always be immediately available.
// This is only for documentation purpose,
// until we have a proper type some day.
template <typename T>
using expected = tc::future<T>;

class AsyncCore
{
public:
  AsyncCore(AsyncCore const&) = delete;
  AsyncCore(AsyncCore&&) = delete;
  AsyncCore& operator=(AsyncCore const&) = delete;
  AsyncCore& operator=(AsyncCore&&) = delete;

  AsyncCore(std::string url, SdkInfo info, std::string writablePath);
  ~AsyncCore();

  tc::future<void> destroy();

  tc::future<Status> start(std::string const& identity);
  tc::future<void> stop();

  tc::future<std::optional<std::string>> registerIdentity(
      Unlock::Verification const& verification,
      Core::VerifyWithToken withToken = Core::VerifyWithToken::No);
  tc::future<std::optional<std::string>> verifyIdentity(
      Unlock::Verification const& verification,
      Core::VerifyWithToken withToken = Core::VerifyWithToken::No);

  tc::future<std::string> getSessionToken(
      Unlock::Verification const& verification,
      std::string const& withTokenNonce);

  Tanker::Status status() const;

  tc::future<void> encrypt(
      uint8_t* encryptedData,
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {},
      Core::ShareWithSelf shareWithSelf = Core::ShareWithSelf::Yes);
  tc::future<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::future<std::vector<uint8_t>> encrypt(
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {},
      Core::ShareWithSelf shareWithSelf = Core::ShareWithSelf::Yes);

  tc::future<std::vector<uint8_t>> decrypt(
      gsl::span<uint8_t const> encryptedData);

  tc::future<void> share(std::vector<SResourceId> const& resourceId,
                         std::vector<SPublicIdentity> const& publicIdentities,
                         std::vector<SGroupId> const& groupIds);

  tc::future<SGroupId> createGroup(std::vector<SPublicIdentity> const& members);
  tc::future<void> updateGroupMembers(
      SGroupId const& groupId,
      std::vector<SPublicIdentity> const& usersToAdd,
      std::vector<SPublicIdentity> const& usersToRemove);

  tc::future<VerificationKey> generateVerificationKey();

  tc::future<std::optional<std::string>> setVerificationMethod(
      Unlock::Verification const& method,
      Core::VerifyWithToken withToken = Core::VerifyWithToken::No);
  tc::future<std::vector<Unlock::VerificationMethod>> getVerificationMethods();

  tc::future<AttachResult> attachProvisionalIdentity(
      SSecretProvisionalIdentity const& sidentity);
  tc::future<void> verifyProvisionalIdentity(
      Unlock::Verification const& verification);

  void connectSessionClosed(std::function<void()> cb);
  void disconnectSessionClosed();
  void connectDeviceRevoked(std::function<void()> cb);
  void disconnectDeviceRevoked();

  tc::future<SDeviceId> deviceId() const;
  tc::future<std::vector<Users::Device>> getDeviceList();

  tc::future<void> revokeDevice(SDeviceId const& deviceId);

  static void setLogHandler(Log::LogHandler handler);

  static uint64_t encryptedSize(uint64_t clearSize);

  static expected<uint64_t> decryptedSize(
      gsl::span<uint8_t const> encryptedData);

  tc::future<Streams::EncryptionStream> makeEncryptionStream(
      Streams::InputSource,
      std::vector<SPublicIdentity> const& suserIds = {},
      std::vector<SGroupId> const& sgroupIds = {},
      Core::ShareWithSelf shareWithSelf = Core::ShareWithSelf::Yes);

  tc::future<Streams::DecryptionStreamAdapter> makeDecryptionStream(
      Streams::InputSource);

  tc::future<EncryptionSession> makeEncryptionSession(
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {},
      Core::ShareWithSelf shareWithSelf = Core::ShareWithSelf::Yes);

  static expected<SResourceId> getResourceId(
      gsl::span<uint8_t const> encryptedData);

  static std::string const& version();

  tc::future<void> setHttpSessionToken(std::string token);

private:
  Core _core;

  // this signal is special compared to the other two because we need to do
  // special work before forwarding it, so we redefine it
  std::function<void()> _asyncDeviceRevoked;

  tc::semaphore _quickStopSemaphore{1};

  mutable tc::lazy::task_canceler _taskCanceler;

  [[noreturn]] tc::cotask<void> handleDeviceRevocation();
  tc::cotask<void> handleDeviceUnrecoverable();
  void nukeAndStop();

  template <typename F>
  auto runResumable(F&& f);
};
}
