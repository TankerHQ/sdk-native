#include <Tanker/Core.hpp>

#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Opener.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Registration.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <exception>
#include <iterator>

#define INVALID_STATUS(action)                               \
  Errors::formatEx(Errors::Errc::PreconditionFailed,         \
                   TFMT("invalid status {:e} for " #action), \
                   status())

TLOG_CATEGORY(Core);

namespace Tanker
{
Core::Core(std::string url, Network::SdkInfo info, std::string writablePath)
  : _url(std::move(url)),
    _info(std::move(info)),
    _writablePath(std::move(writablePath)),
    _state(boost::variant2::in_place_type<Opener>, _url, _info, _writablePath)
{
}

Status Core::status() const
{
  if (_state.valueless_by_exception())
    throw Errors::AssertionError("_state variant must not be valueless");
  if (auto core = boost::variant2::get_if<Opener>(&_state))
    return core->status();
  else if (boost::variant2::get_if<SessionType>(&_state))
    return Status::Ready;
  throw Errors::AssertionError("unreachable code: invalid Tanker status");
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
  throw Errors::AssertionError("unreachable code in resetOnFailure");
}

tc::cotask<Status> Core::startImpl(std::string const& identity)
{
  auto pcore = boost::variant2::get_if<Opener>(&_state);
  if (!pcore)
    throw INVALID_STATUS(start);

  auto status = TC_AWAIT(pcore->open(identity));
  if (status == Status::Ready)
  {
    initSession(TC_AWAIT(pcore->openDevice()));
    auto const& session = boost::variant2::get<SessionType>(_state);
    TC_AWAIT(session->startConnection());
    TC_RETURN(Status::Ready);
  }
  TC_RETURN(status);
}

tc::cotask<Status> Core::start(std::string const& identity)
{
  SCOPE_TIMER("core_start", Proc);
  TC_RETURN(TC_AWAIT(resetOnFailure([&]() -> tc::cotask<Status> {
    TC_RETURN(TC_AWAIT(startImpl(identity)));
  })));
}

tc::cotask<void> Core::registerIdentity(
    Unlock::Verification const& verification)
{
  auto pcore = boost::variant2::get_if<Opener>(&_state);
  if (!pcore)
    throw INVALID_STATUS(start);

  auto openResult = TC_AWAIT(pcore->createUser(verification));
  initSession(std::move(openResult));
  auto const& session = boost::variant2::get<SessionType>(_state);
  TC_AWAIT(session->startConnection());
}

tc::cotask<void> Core::verifyIdentity(Unlock::Verification const& verification)
{
  SCOPE_TIMER("verify_identity", Proc);
  auto pcore = boost::variant2::get_if<Opener>(&_state);
  if (!pcore)
    throw INVALID_STATUS(verifyIdentity);

  auto openResult = TC_AWAIT(pcore->createDevice(verification));
  initSession(std::move(openResult));
  auto const& session = boost::variant2::get<SessionType>(_state);
  TC_AWAIT(session->startConnection());
}

void Core::stop()
{
  reset();
  if (_sessionClosed)
    _sessionClosed();
}

void Core::initSession(Session::Config config)
{
  _state.emplace<SessionType>(std::make_unique<Session>(std::move(config)));
  auto const& session = boost::variant2::get<SessionType>(_state);
  session->deviceRevoked = _deviceRevoked;
}

void Core::setDeviceRevokedHandler(Session::DeviceRevokedHandler handler)
{
  _deviceRevoked = std::move(handler);
  if (auto const session = boost::variant2::get_if<SessionType>(&_state))
    (*session)->deviceRevoked = _deviceRevoked; // we need the copy here
}

void Core::setSessionClosedHandler(SessionClosedHandler handler)
{
  _sessionClosed = std::move(handler);
}

void Core::reset()
{
  _state.emplace<Opener>(_url, _info, _writablePath);
}

tc::cotask<void> Core::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(encrypt);
  TC_AWAIT((*psession)->encrypt(
      encryptedData, clearData, publicIdentities, groupIds));
}

tc::cotask<std::vector<uint8_t>> Core::encrypt(
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(encrypt);
  TC_RETURN(
      TC_AWAIT((*psession)->encrypt(clearData, publicIdentities, groupIds)));
}

tc::cotask<void> Core::decrypt(uint8_t* decryptedData,
                               gsl::span<uint8_t const> encryptedData)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(decrypt);
  TC_AWAIT((*psession)->decrypt(decryptedData, encryptedData));
}

tc::cotask<std::vector<uint8_t>> Core::decrypt(
    gsl::span<uint8_t const> encryptedData)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(decrypt);
  TC_RETURN(TC_AWAIT((*psession)->decrypt(encryptedData)));
}

tc::cotask<void> Core::share(
    std::vector<SResourceId> const& sresourceIds,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(share);
  TC_AWAIT((*psession)->share(sresourceIds, publicIdentities, groupIds));
}

tc::cotask<SGroupId> Core::createGroup(
    std::vector<SPublicIdentity> const& members)
{
  auto const psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(createGroup);
  return (*psession)->createGroup(members);
}

tc::cotask<void> Core::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> const& usersToAdd)
{
  auto const psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(updateGroupMembers);
  return (*psession)->updateGroupMembers(groupIdString, usersToAdd);
}

Trustchain::DeviceId const& Core::deviceId() const
{
  auto const psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(deviceId);
  return (*psession)->deviceId();
  ;
}

tc::cotask<std::vector<Device>> Core::getDeviceList() const
{
  auto const psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(getDeviceList);
  return (*psession)->getDeviceList();
}

tc::cotask<VerificationKey> Core::generateVerificationKey()
{
  auto pcore = boost::variant2::get_if<Opener>(&_state);
  if (!pcore)
    throw INVALID_STATUS(generateVerificationKey);
  TC_RETURN(TC_AWAIT(pcore->generateVerificationKey()));
}

tc::cotask<void> Core::setVerificationMethod(Unlock::Verification const& method)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(setVerificationMethod);
  TC_AWAIT((*psession)->setVerificationMethod(method));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Core::getVerificationMethods()
{
  auto const st = status();
  if (st != Status::Ready && st != Status::IdentityVerificationNeeded)
    throw INVALID_STATUS(getVerificationMethods);
  if (auto psession = boost::variant2::get_if<SessionType>(&_state))
    TC_RETURN(TC_AWAIT((*psession)->fetchVerificationMethods()));
  else if (auto pcore = boost::variant2::get_if<Opener>(&_state))
    TC_RETURN(TC_AWAIT(pcore->fetchVerificationMethods()));
  throw Errors::AssertionError("unreachable code: getVerificationMethods");
}

tc::cotask<AttachResult> Core::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(attachProvisionalIdentity);
  TC_RETURN(TC_AWAIT((*psession)->attachProvisionalIdentity(sidentity)));
}

tc::cotask<void> Core::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(verifyProvisionalIdentity);
  TC_AWAIT((*psession)->verifyProvisionalIdentity(verification));
}

tc::cotask<void> Core::syncTrustchain()
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(syncTrustchain);
  TC_AWAIT((*psession)->syncTrustchain());
}

tc::cotask<void> Core::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(revokeDevice);
  TC_AWAIT((*psession)->revokeDevice(deviceId));
}

tc::cotask<Streams::EncryptionStream> Core::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& suserIds,
    std::vector<SGroupId> const& sgroupIds)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(makeEncryptionStream);
  TC_RETURN(TC_AWAIT(
      (*psession)->makeEncryptionStream(std::move(cb), suserIds, sgroupIds)));
}

tc::cotask<Streams::DecryptionStreamAdapter> Core::makeDecryptionStream(
    Streams::InputSource cb)
{
  auto psession = boost::variant2::get_if<SessionType>(&_state);
  if (!psession)
    throw INVALID_STATUS(makeDecryptionStream);
  TC_RETURN(TC_AWAIT((*psession)->makeDecryptionStream(std::move(cb))));
}

Trustchain::ResourceId Core::getResourceId(
    gsl::span<uint8_t const> encryptedData)
{
  return Encryptor::extractResourceId(encryptedData);
}
}
