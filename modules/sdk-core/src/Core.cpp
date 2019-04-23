#include <Tanker/Core.hpp>

#include <Tanker/Encryptor.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Opener.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Unlock/Registration.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <exception>
#include <iterator>

#define INVALID_STATUS(action)                 \
  Error::formatEx<Error::InvalidTankerStatus>( \
      fmt("invalid status {:e} for " #action), status())

TLOG_CATEGORY(Core);

namespace Tanker
{
Core::Core(std::string url, SdkInfo info, std::string writablePath)
  : _url(std::move(url)),
    _info(std::move(info)),
    _writablePath(std::move(writablePath)),
    _state(mpark::in_place_type<Opener>, _url, _info, _writablePath)
{
}

Status Core::status() const
{
  assert(!_state.valueless_by_exception() &&
         "_state variant must not be valueless");
  if (mpark::get_if<Opener>(&_state))
    return Status::Closed;
  else if (mpark::get_if<SessionType>(&_state))
    return Status::Open;
  TERROR("unreachable code, invalid tanker status");
  std::terminate();
}

bool Core::isOpen() const
{
  return this->status() == Status::Open;
}

template <typename F>
decltype(std::declval<F>()()) Core::resetOnFailure(F&& f)
{
  std::exception_ptr exception;
  try
  {
    TC_RETURN(TC_AWAIT(f()));
  }
  catch (...)
  {
    exception = std::current_exception();
  }
  if (exception)
  {
    // reset() does context switches, but it is forbidden to do them in catch
    // clauses, so we retain the exception and call reset() outside of the catch
    // clause
    reset();
    std::rethrow_exception(exception);
  }
  throw std::runtime_error("unreachable code");
}

tc::cotask<void> Core::signUp(std::string const& identity,
                              AuthenticationMethods const& authMethods)
{
  SCOPE_TIMER("core_signup", Proc);
  TC_AWAIT(resetOnFailure([&]() -> tc::cotask<tc::tvoid> {
    TC_AWAIT(signUpImpl(identity, authMethods));
    TC_RETURN(tc::tvoid{});
  }));
}

tc::cotask<void> Core::signUpImpl(std::string const& identity,
                                  AuthenticationMethods const& authMethods)
{
  auto pcore = mpark::get_if<Opener>(&_state);
  if (!pcore)
    throw INVALID_STATUS(signUp);
  auto openResult = TC_AWAIT(pcore->open(identity, {}, OpenMode::SignUp));
  assert(mpark::holds_alternative<Session::Config>(openResult));
  initSession(std::move(openResult));
  auto const& session = mpark::get<SessionType>(_state);
  TC_AWAIT(session->startConnection());
  if (authMethods.password || authMethods.email)
  {
    Unlock::RegistrationOptions options{};
    if (authMethods.password)
      options.set(*authMethods.password);
    if (authMethods.email)
      options.set(*authMethods.email);
    TC_AWAIT(session->registerUnlock(options));
  }
}

tc::cotask<OpenResult> Core::signIn(std::string const& identity,
                                    SignInOptions const& signInOptions)
{
  SCOPE_TIMER("core_signin", Proc);
  TC_RETURN(TC_AWAIT(resetOnFailure([&]() -> tc::cotask<OpenResult> {
    TC_RETURN(TC_AWAIT(signInImpl(identity, signInOptions)));
  })));
}

tc::cotask<OpenResult> Core::signInImpl(std::string const& identity,
                                        SignInOptions const& signInOptions)
{
  auto pcore = mpark::get_if<Opener>(&_state);
  if (!pcore)
    throw INVALID_STATUS(signIn);
  auto openResult =
      TC_AWAIT(pcore->open(identity, signInOptions, OpenMode::SignIn));
  if (mpark::holds_alternative<Opener::StatusIdentityNotRegistered>(openResult))
  {
    reset();
    TC_RETURN(OpenResult::IdentityNotRegistered);
  }
  else if (mpark::holds_alternative<Opener::StatusIdentityVerificationNeeded>(
               openResult))
  {
    reset();
    TC_RETURN(OpenResult::IdentityVerificationNeeded);
  }
  initSession(std::move(openResult));
  auto const& session = mpark::get<SessionType>(_state);
  TC_AWAIT(session->startConnection());
  TC_RETURN(OpenResult::Ok);
}

void Core::signOut()
{
  reset();
  sessionClosed();
}

void Core::initSession(Opener::OpenResult&& openResult)
{
  _state.emplace<SessionType>(std::make_unique<Session>(
      mpark::get<Session::Config>(std::move(openResult))));
  auto const& session = mpark::get<SessionType>(_state);
  session->deviceRevoked.connect(deviceRevoked);
  session->gotDeviceId.connect(
      [this](auto const& deviceId) { _deviceId = deviceId; });
}

void Core::reset()
{
  _state.emplace<Opener>(_url, _info, _writablePath);
  _deviceId = Trustchain::DeviceId{};
}

tc::cotask<void> Core::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(encrypt);
  TC_AWAIT((*psession)->encrypt(
      encryptedData, clearData, publicIdentities, groupIds));
}

tc::cotask<void> Core::decrypt(uint8_t* decryptedData,
                               gsl::span<uint8_t const> encryptedData)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(decrypt);
  TC_AWAIT((*psession)->decrypt(decryptedData, encryptedData));
}

tc::cotask<void> Core::share(
    std::vector<SResourceId> const& sresourceIds,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(share);
  TC_AWAIT((*psession)->share(sresourceIds, publicIdentities, groupIds));
}

tc::cotask<SGroupId> Core::createGroup(
    std::vector<SPublicIdentity> const& members)
{
  auto const psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(createGroup);
  return (*psession)->createGroup(members);
}

tc::cotask<void> Core::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> const& usersToAdd)
{
  auto const psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(updateGroupMembers);
  return (*psession)->updateGroupMembers(groupIdString, usersToAdd);
}

Trustchain::DeviceId const& Core::deviceId() const
{
  if (!isOpen())
    throw INVALID_STATUS(deviceId);
  else
    return _deviceId;
}

tc::cotask<std::vector<Device>> Core::getDeviceList() const
{
  auto const psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(getDeviceList);
  return (*psession)->getDeviceList();
}

tc::cotask<UnlockKey> Core::generateAndRegisterUnlockKey()
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(generateAndRegisterUnlockKey);
  TC_RETURN(TC_AWAIT((*psession)->generateAndRegisterUnlockKey()));
}

tc::cotask<void> Core::registerUnlock(
    Unlock::RegistrationOptions const& options)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(registerUnlock);
  TC_AWAIT((*psession)->registerUnlock(options));
}

tc::cotask<bool> Core::isUnlockAlreadySetUp() const
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(isUnlockAlreadySetUp);
  TC_RETURN(TC_AWAIT((*psession)->isUnlockAlreadySetUp()));
}

Unlock::Methods Core::registeredUnlockMethods() const
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(registeredUnlockMethods);
  return (*psession)->registeredUnlockMethods();
}

tc::cotask<void> Core::claimProvisionalIdentity(
    SSecretProvisionalIdentity const& identity,
    VerificationCode const& verificationCode)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(registeredUnlockMethods);
  TC_AWAIT((*psession)->claimProvisionalIdentity(identity, verificationCode));
}

bool Core::hasRegisteredUnlockMethods() const
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(hasRegisteredUnlockMethods);
  return (*psession)->hasRegisteredUnlockMethods();
}

bool Core::hasRegisteredUnlockMethod(Unlock::Method method) const
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(hasRegisteredUnlockMethod);
  return (*psession)->hasRegisteredUnlockMethod(method);
}

tc::cotask<void> Core::syncTrustchain()
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(syncTrustchain);
  TC_AWAIT((*psession)->syncTrustchain());
}

tc::cotask<void> Core::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(revokeDevice);
  TC_AWAIT((*psession)->revokeDevice(deviceId));
}

SResourceId Core::getResourceId(gsl::span<uint8_t const> encryptedData)
{
  return cppcodec::base64_rfc4648::encode<SResourceId>(
      Encryptor::extractResourceId(encryptedData));
}
}
