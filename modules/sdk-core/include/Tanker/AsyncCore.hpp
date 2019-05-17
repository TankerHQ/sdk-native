#pragma once

#include <Tanker/Core.hpp>
#include <Tanker/LogHandler.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/SDeviceId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>
#include <Tanker/Unlock/Methods.hpp>

#include <Tanker/task_canceler.hpp>

#include <tconcurrent/future.hpp>

#include <gsl-lite.hpp>

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

  tc::shared_future<Status> start(std::string const& identity);
  tc::shared_future<void> stop();

  tc::shared_future<void> registerIdentity(
      Unlock::Verification const& verification);
  tc::shared_future<void> verifyIdentity(
      Unlock::Verification const& verification);

  Tanker::Status status() const;

  tc::shared_future<void> encrypt(
      uint8_t* encryptedData,
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});
  tc::shared_future<void> decrypt(uint8_t* decryptedData,
                                  gsl::span<uint8_t const> encryptedData);

  tc::shared_future<void> share(
      std::vector<SResourceId> const& resourceId,
      std::vector<SPublicIdentity> const& publicIdentities,
      std::vector<SGroupId> const& groupIds);

  tc::shared_future<SGroupId> createGroup(
      std::vector<SPublicIdentity> const& members);
  tc::shared_future<void> updateGroupMembers(
      SGroupId const& groupId, std::vector<SPublicIdentity> const& usersToAdd);

  tc::shared_future<VerificationKey> generateVerificationKey();

  tc::shared_future<void> setVerificationMethod(
      Unlock::Verification const& method);

  tc::shared_future<bool> isUnlockAlreadySetUp() const;
  expected<bool> hasRegisteredUnlockMethods() const;
  expected<bool> hasRegisteredUnlockMethod(Unlock::Method) const;
  expected<Unlock::Methods> registeredUnlockMethods() const;

  tc::shared_future<void> claimProvisionalIdentity(
      SSecretProvisionalIdentity const& identity,
      VerificationCode const& verificationCode);

  void connectSessionClosed(std::function<void()> cb);
  void disconnectSessionClosed();
  void connectDeviceRevoked(std::function<void()> cb);
  void disconnectDeviceRevoked();

  expected<SDeviceId> deviceId() const;
  tc::shared_future<std::vector<Device>> getDeviceList();

  tc::shared_future<void> revokeDevice(SDeviceId const& deviceId);

  tc::shared_future<void> syncTrustchain();

  static void setLogHandler(Log::LogHandler handler);

  static uint64_t encryptedSize(uint64_t clearSize);

  static expected<uint64_t> decryptedSize(
      gsl::span<uint8_t const> encryptedData);

  static expected<SResourceId> getResourceId(
      gsl::span<uint8_t const> encryptedData);

  static std::string const& version();

private:
  Core _core;

  // this signal is special compared to the other two because we need to do
  // special work before forwarding it, so we redefine it
  std::function<void()> _asyncDeviceRevoked;

  mutable task_canceler _taskCanceler;
};
}
