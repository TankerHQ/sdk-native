#pragma once

#include <Tanker/Opener.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>
#include <Tanker/Unlock/Options.hpp>

#include <boost/signals2/signal.hpp>
#include <gsl-lite.hpp>
#include <mpark/variant.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
class Core
{
public:
  Core(std::string url, SdkInfo infos, std::string writablePath);

  Status status() const;

  tc::cotask<void> open(SUserId const& suserId, std::string const& userToken);
  void close();

  tc::cotask<void> encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData,
                           std::vector<SUserId> const& userIds = {},
                           std::vector<SGroupId> const& groupIds = {});

  tc::cotask<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> share(std::vector<SResourceId> const& resourceId,
                         std::vector<SUserId> const& userIds,
                         std::vector<SGroupId> const& groupIds);

  tc::cotask<SGroupId> createGroup(std::vector<SUserId> const& members);
  tc::cotask<void> updateGroupMembers(SGroupId const& groupId,
                                      std::vector<SUserId> const& usersToAdd);

  tc::cotask<UnlockKey> generateAndRegisterUnlockKey();

  tc::cotask<void> registerUnlock(Unlock::RegistrationOptions const& options);
  tc::cotask<void> unlockCurrentDevice(Unlock::DeviceLocker const& pass);
  tc::cotask<bool> isUnlockAlreadySetUp() const;
  bool hasRegisteredUnlockMethods() const;
  bool hasRegisteredUnlockMethods(Unlock::Method) const;
  Unlock::Methods registeredUnlockMethods() const;

  DeviceId const& deviceId() const;

  tc::cotask<void> syncTrustchain();

  tc::cotask<void> revokeDevice(DeviceId const& deviceId);

  boost::signals2::signal<void()> unlockRequired;
  boost::signals2::signal<void()> sessionClosed;
  boost::signals2::signal<void()> deviceCreated;
  boost::signals2::signal<void()> deviceRevoked;

  static SResourceId getResourceId(gsl::span<uint8_t const> encryptedData);

private:
  // We store the session as a unique_ptr so that open() does not
  // emplace<Session>. The Session constructor is asynchronous, so the user
  // could try to observe the variant state while it is emplacing. variant is
  // not reentrant so the observation would trigger undefined behavior.
  using SessionType = std::unique_ptr<Session>;

  std::string _url;
  SdkInfo _info;
  std::string _writablePath;

  mpark::variant<Opener, SessionType> _state;

  tc::task_auto_canceler _taskCanceler;

  void reset();
};
}
