#include <Tanker/Core.hpp>

#include <Tanker/ChunkEncryptor.hpp>
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
  reset();
}

void Core::reset()
{
  mpark::get<Opener>(_state).unlockRequired.connect([this] {
    if (unlockRequired.empty())
    {
      throw Error::formatEx<Error::InvalidUnlockEventHandler>(
          "No unlock handler registered");
    }
    unlockRequired();
  });
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

tc::cotask<void> Core::open(SUserId const& suserId,
                            std::string const& userToken)
{
  SCOPE_TIMER("core_open", Proc);
  auto pcore = mpark::get_if<Opener>(&_state);
  if (!pcore)
    throw INVALID_STATUS(open);
  _state.emplace<SessionType>(
      std::make_unique<Session>(TC_AWAIT(pcore->open(suserId, userToken))));
  auto const& session = mpark::get<SessionType>(_state);
  session->deviceCreated.connect(deviceCreated);
  session->deviceRevoked.connect([&] {
    _taskCanceler.add(tc::async([this] {
      close();
      deviceRevoked();
    }));
  });
  TC_AWAIT(session->startConnection());
}

void Core::close()
{
  _state.emplace<Opener>(_url, _info, _writablePath);
  sessionClosed();
  reset();
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
  auto const& ret = (*psession)->deviceId();
  // HOTFIX
  if (ret == DeviceId{})
  {
    throw Error::formatEx<Error::DeviceNotFound>(
        "Device is not fully initialized, please wait for open to finish");
  }
  return ret;
}

tc::cotask<UnlockKey> Core::generateAndRegisterUnlockKey()
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(generateAndRegisterUnlockKey);
  TC_RETURN(TC_AWAIT((*psession)->generateAndRegisterUnlockKey()));
}

tc::cotask<void> Core::setupUnlock(Unlock::CreationOptions const& options)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(setupUnlock);
  TC_AWAIT((*psession)->createUnlockKey(options));
}

tc::cotask<void> Core::updateUnlock(Unlock::UpdateOptions const& options)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(updateUnlock);
  TC_AWAIT((*psession)->updateUnlock(options));
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

std::unique_ptr<ChunkEncryptor> Core::makeChunkEncryptor()
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(makeChunkEncryptor);
  return (*psession)->makeChunkEncryptor();
}

tc::cotask<std::unique_ptr<ChunkEncryptor>> Core::makeChunkEncryptor(
    gsl::span<uint8_t const> encryptedSeal)
{
  auto psession = mpark::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(makeChunkEncryptor);
  TC_RETURN(TC_AWAIT((*psession)->makeChunkEncryptor(encryptedSeal)));
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
