#include <Tanker/Core.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/EnumFormat.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Opener.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Unlock/Registration.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

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
  if (auto core = mpark::get_if<Opener>(&_state))
    return core->status();
  else if (mpark::get_if<SessionType>(&_state))
    return Status::Open;
  TERROR("unreachable code, invalid tanker status");
  std::terminate();
}

tc::cotask<void> Core::signUp(std::string const& identity,
                              AuthenticationMethods const& authMethods)
{
  SCOPE_TIMER("core_signup", Proc);
  try
  {
    auto pcore = mpark::get_if<Opener>(&_state);
    if (!pcore)
      throw INVALID_STATUS(signUp);
    auto openResult = TC_AWAIT(pcore->open(identity, {}, OpenMode::SignUp));
    assert(mpark::holds_alternative<Session::Config>(openResult));
    _state.emplace<SessionType>(std::make_unique<Session>(
        mpark::get<Session::Config>(std::move(openResult))));
    auto const& session = mpark::get<SessionType>(_state);
    session->deviceCreated.connect(deviceCreated);
    session->deviceRevoked.connect([&] {
      _taskCanceler.add(tc::async([this] {
        close();
        deviceRevoked();
      }));
    });
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
  catch (...)
  {
    _state.emplace<Opener>(_url, _info, _writablePath);
    throw;
  }
}

tc::cotask<OpenResult> Core::signIn(std::string const& identity,
                                    SignInOptions const& signInOptions)
{
  SCOPE_TIMER("core_signin", Proc);
  try
  {
    auto pcore = mpark::get_if<Opener>(&_state);
    if (!pcore)
      throw INVALID_STATUS(signIn);
    auto openResult =
        TC_AWAIT(pcore->open(identity, signInOptions, OpenMode::SignIn));
    if (mpark::holds_alternative<Opener::StatusIdentityNotRegistered>(
            openResult))
    {
      _state.emplace<Opener>(_url, _info, _writablePath);
      TC_RETURN(OpenResult::IdentityNotRegistered);
    }
    else if (mpark::holds_alternative<Opener::StatusIdentityVerificationNeeded>(
                 openResult))
    {
      _state.emplace<Opener>(_url, _info, _writablePath);
      TC_RETURN(OpenResult::IdentityVerificationNeeded);
    }
    _state.emplace<SessionType>(std::make_unique<Session>(
        mpark::get<Session::Config>(std::move(openResult))));
    auto const& session = mpark::get<SessionType>(_state);
    session->deviceCreated.connect(deviceCreated);
    session->deviceRevoked.connect([&] {
      _taskCanceler.add(tc::async([this] {
        close();
        deviceRevoked();
      }));
    });
    TC_AWAIT(session->startConnection());
    TC_RETURN(OpenResult::Ok);
  }
  catch (...)
  {
    _state.emplace<Opener>(_url, _info, _writablePath);
    throw;
  }
}

void Core::close()
{
  _state.emplace<Opener>(_url, _info, _writablePath);
  sessionClosed();
}

tc::cotask<void> Core::encrypt(uint8_t* encryptedData,
                               gsl::span<uint8_t const> clearData,
                               std::vector<SUserId> const& userIds,
                               std::vector<SGroupId> const& groupIds)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(encrypt);
  TC_AWAIT((*psession)->encrypt(encryptedData, clearData, userIds, groupIds));
}

tc::cotask<void> Core::decrypt(uint8_t* decryptedData,
                               gsl::span<uint8_t const> encryptedData)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(decrypt);
  TC_AWAIT((*psession)->decrypt(decryptedData, encryptedData));
}

tc::cotask<void> Core::share(std::vector<SResourceId> const& sresourceIds,
                             std::vector<SUserId> const& userIds,
                             std::vector<SGroupId> const& groupIds)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(share);
  TC_AWAIT((*psession)->share(sresourceIds, userIds, groupIds));
}

tc::cotask<SGroupId> Core::createGroup(std::vector<SUserId> const& members)
{
  auto const psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(createGroup);
  return (*psession)->createGroup(members);
}

tc::cotask<void> Core::updateGroupMembers(
    SGroupId const& groupIdString, std::vector<SUserId> const& usersToAdd)
{
  auto const psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(updateGroupMembers);
  return (*psession)->updateGroupMembers(groupIdString, usersToAdd);
}

DeviceId const& Core::deviceId() const
{
  auto const psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(deviceId);
  return (*psession)->deviceId();
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

tc::cotask<void> Core::unlockCurrentDevice(Unlock::DeviceLocker const& locker)
{
  auto popener = mpark::get_if<Opener>(&_state);
  if (!popener)
    throw INVALID_STATUS(unlockCurrentDevice);
  auto const unlockKey = mpark::holds_alternative<UnlockKey>(locker) ?
                             mpark::get<UnlockKey>(locker) :
                             TC_AWAIT(popener->fetchUnlockKey(locker));
  TC_AWAIT(popener->unlockCurrentDevice(unlockKey));
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

bool Core::hasRegisteredUnlockMethods() const
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(hasRegisteredUnlockMethods);
  return (*psession)->hasRegisteredUnlockMethods();
}

bool Core::hasRegisteredUnlockMethods(Unlock::Method method) const
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(hasRegisteredUnlockMethods);
  return (*psession)->hasRegisteredUnlockMethods(method);
}

tc::cotask<void> Core::syncTrustchain()
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(syncTrustchain);
  TC_AWAIT((*psession)->syncTrustchain());
}

tc::cotask<void> Core::revokeDevice(DeviceId const& deviceId)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(revokeDevice);
  TC_AWAIT((*psession)->revokeDevice(deviceId));
}

SResourceId Core::getResourceId(gsl::span<uint8_t const> encryptedData)
{
  return base64::encode<SResourceId>(
      Encryptor::extractResourceId(encryptedData));
}
}
