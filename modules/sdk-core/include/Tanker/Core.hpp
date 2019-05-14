#pragma once

#include <Tanker/Opener.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
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
struct AuthenticationMethods
{
  nonstd::optional<Password> password;
  nonstd::optional<Email> email;
};

enum OpenResult
{
  Ok,
  IdentityNotRegistered,
  IdentityVerificationNeeded,

  Last,
};

class Core
{
public:
  Core(std::string url, SdkInfo infos, std::string writablePath);

  tc::cotask<void> signUp(std::string const& identity,
                          AuthenticationMethods const& authMethods);
  tc::cotask<OpenResult> signIn(std::string const& identity,
                                SignInOptions const& signInOptions);
  void stop();

  bool isOpen() const;

  tc::cotask<void> encrypt(
      uint8_t* encryptedData,
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});

  tc::cotask<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> share(std::vector<SResourceId> const& resourceId,
                         std::vector<SPublicIdentity> const& publicIdentities,
                         std::vector<SGroupId> const& groupIds);

  tc::cotask<SGroupId> createGroup(std::vector<SPublicIdentity> const& members);
  tc::cotask<void> updateGroupMembers(
      SGroupId const& groupId, std::vector<SPublicIdentity> const& usersToAdd);

  tc::cotask<VerificationKey> generateAndRegisterVerificationKey();

  tc::cotask<void> registerUnlock(Unlock::RegistrationOptions const& options);
  tc::cotask<void> unlockCurrentDevice(Unlock::DeviceLocker const& pass);
  tc::cotask<bool> isUnlockAlreadySetUp() const;
  bool hasRegisteredUnlockMethods() const;
  bool hasRegisteredUnlockMethod(Unlock::Method) const;
  Unlock::Methods registeredUnlockMethods() const;
  tc::cotask<void> claimProvisionalIdentity(
      SSecretProvisionalIdentity const& identity,
      VerificationCode const& verificationCode);

  Trustchain::DeviceId const& deviceId() const;
  tc::cotask<std::vector<Device>> getDeviceList() const;

  tc::cotask<void> syncTrustchain();

  tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId);

  boost::signals2::signal<void()> sessionClosed;
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

  Trustchain::DeviceId _deviceId{};

  void reset();
  void initSession(Opener::OpenResult&& openResult);
  Status status() const;

  template <typename F>
  decltype(std::declval<F>()()) resetOnFailure(F&& f);

  tc::cotask<void> signUpImpl(std::string const& identity,
                              AuthenticationMethods const& authMethods);
  tc::cotask<OpenResult> signInImpl(std::string const& identity,
                                    SignInOptions const& signInOptions);
};
}
