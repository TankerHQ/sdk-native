#pragma once

#include <Tanker/Core.hpp>
#include <Tanker/LogHandler.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/SDeviceId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>
#include <Tanker/Unlock/Methods.hpp>
#include <Tanker/Unlock/Options.hpp>

#include <tconcurrent/future.hpp>

#include <boost/signals2/connection.hpp>
#include <boost/signals2/signal.hpp>
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

enum class Event
{
  SessionClosed,
  DeviceCreated,
  DeviceRevoked,

  Last
};

class AsyncCore
{
public:
  AsyncCore(std::string url, SdkInfo info, std::string writablePath);
  ~AsyncCore();

  tc::future<void> destroy();

  expected<boost::signals2::scoped_connection> connectEvent(
      Event event, std::function<void(void*, void*)> cb, void* data = nullptr);

  expected<void> disconnectEvent(boost::signals2::scoped_connection conn);

  tc::future<void> signUp(std::string const& identity,
                          AuthenticationMethods const& authMethods = {});
  tc::future<OpenResult> signIn(std::string const& identity,
                                SignInOptions const& signInOptions = {});

  tc::future<void> signOut();

  bool isOpen() const;

  tc::future<void> encrypt(
      uint8_t* encryptedData,
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});
  tc::future<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::future<void> share(std::vector<SResourceId> const& resourceId,
                         std::vector<SPublicIdentity> const& publicIdentities,
                         std::vector<SGroupId> const& groupIds);

  tc::future<SGroupId> createGroup(std::vector<SPublicIdentity> const& members);
  tc::future<void> updateGroupMembers(
      SGroupId const& groupId, std::vector<SPublicIdentity> const& usersToAdd);

  tc::future<UnlockKey> generateAndRegisterUnlockKey();

  tc::future<void> registerUnlock(Unlock::RegistrationOptions const& options);

  tc::future<bool> isUnlockAlreadySetUp() const;
  expected<bool> hasRegisteredUnlockMethods() const;
  expected<bool> hasRegisteredUnlockMethod(Unlock::Method) const;
  expected<Unlock::Methods> registeredUnlockMethods() const;

  boost::signals2::signal<void()>& sessionClosed();
  boost::signals2::signal<void()>& deviceCreated();
  boost::signals2::signal<void()>& deviceRevoked();

  tc::future<SDeviceId> deviceId() const;

  tc::future<void> revokeDevice(SDeviceId const& deviceId);

  tc::future<void> syncTrustchain();

  static void setLogHandler(Log::LogHandler handler);

  static uint64_t encryptedSize(uint64_t clearSize);

  static expected<uint64_t> decryptedSize(
      gsl::span<uint8_t const> encryptedData);

  static expected<SResourceId> getResourceId(
      gsl::span<uint8_t const> encryptedData);

  static std::string const& version();

private:
  std::unique_ptr<Core> _core;
};
}
