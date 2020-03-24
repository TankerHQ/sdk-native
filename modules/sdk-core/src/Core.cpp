#include <Tanker/Core.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Users/Requester.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <exception>

#define checkStatus(wanted, action) this->assertStatus(wanted, #action)

TLOG_CATEGORY(Core);

namespace Tanker
{
namespace
{
}
Core::~Core() = default;

Core::Core(std::string url, Network::SdkInfo info, std::string writablePath)
  : _url(std::move(url)),
    _info(std::move(info)),
    _writablePath(std::move(writablePath)),
    _session(std::make_unique<Session>(_url, _info))
{
}

Status Core::status() const
{
  if (!_session)
    return Status::Stopped;
  else
    return _session->status();
}

void Core::assertStatus(Status wanted, std::string const& action) const
{
  if (auto const s = status(); s != wanted)
    throw Errors::formatEx(Errors::Errc::PreconditionFailed,
                           TFMT("invalid session status {:e} for {:s}"),
                           s,
                           action);
}

template <typename F>
decltype(std::declval<F>()()) Core::resetOnFailure(F&& f)
{
  std::exception_ptr exception;
  try
  {
    TC_RETURN(TC_AWAIT(f()));
  }
  catch (Errors::Exception const& ex)
  {
    // DeviceRevoked is handled at AsyncCore's level, so just ignore it here
    if (ex.errorCode() == Errors::Errc::DeviceRevoked)
      throw;
    exception = std::make_exception_ptr(ex);
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

tc::cotask<Status> Core::startImpl(std::string const& b64Identity)
{
  checkStatus(Status::Stopped, start);

  auto identity =
      Identity::extract<Identity::SecretPermanentIdentity>(b64Identity);
  if (identity.trustchainId != _info.trustchainId)
    throw formatEx(Errors::Errc::InvalidArgument,
                   TFMT("identity's trustchain is {:s}, expected {:s}"),
                   identity.trustchainId,
                   _info.trustchainId);

  TC_RETURN(TC_AWAIT(_session->open(identity, _writablePath)));
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
  TC_AWAIT(_session->createUser(verification));
}

tc::cotask<void> Core::verifyIdentity(Unlock::Verification const& verification)
{
  SCOPE_TIMER("verify_identity", Proc);
  TC_AWAIT(_session->createDevice(verification));
}

void Core::stop()
{
  reset();
  if (_sessionClosed)
    _sessionClosed();
}

void Core::setSessionClosedHandler(SessionClosedHandler handler)
{
  _sessionClosed = std::move(handler);
}

void Core::reset()
{
  _session.reset(new Session{_url, _info});
}

tc::cotask<void> Core::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  checkStatus(Status::Ready, encrypt);
  TC_AWAIT(
      _session->encrypt(encryptedData, clearData, publicIdentities, groupIds));
}

tc::cotask<std::vector<uint8_t>> Core::encrypt(
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  checkStatus(Status::Ready, encrypt);
  TC_RETURN(TC_AWAIT(_session->encrypt(clearData, publicIdentities, groupIds)));
}

tc::cotask<void> Core::decrypt(uint8_t* decryptedData,
                               gsl::span<uint8_t const> encryptedData)
{
  checkStatus(Status::Ready, decrypt);
  TC_AWAIT(_session->decrypt(decryptedData, encryptedData));
}

tc::cotask<std::vector<uint8_t>> Core::decrypt(
    gsl::span<uint8_t const> encryptedData)
{
  checkStatus(Status::Ready, decrypt);
  TC_RETURN(TC_AWAIT(_session->decrypt(encryptedData)));
}

tc::cotask<void> Core::share(
    std::vector<SResourceId> const& sresourceIds,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  checkStatus(Status::Ready, share);
  TC_AWAIT(_session->share(sresourceIds, publicIdentities, groupIds));
}

tc::cotask<SGroupId> Core::createGroup(
    std::vector<SPublicIdentity> const& members)
{
  checkStatus(Status::Ready, createGroup);
  return _session->createGroup(members);
}

tc::cotask<void> Core::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> const& usersToAdd)
{
  checkStatus(Status::Ready, updateGroupMembers);
  return _session->updateGroupMembers(groupIdString, usersToAdd);
}

Trustchain::DeviceId const& Core::deviceId() const
{
  checkStatus(Status::Ready, deviceId);
  return _session->deviceId();
  ;
}

tc::cotask<std::vector<Users::Device>> Core::getDeviceList() const
{
  checkStatus(Status::Ready, getDeviceList);
  return (_session)->getDeviceList();
}

tc::cotask<VerificationKey> Core::generateVerificationKey()
{
  checkStatus(Status::IdentityRegistrationNeeded, generateVerificationKey);
  TC_RETURN(TC_AWAIT(_session->generateVerificationKey()));
}

tc::cotask<void> Core::setVerificationMethod(Unlock::Verification const& method)
{
  checkStatus(Status::Ready, setVerificationMethod);
  TC_AWAIT(_session->setVerificationMethod(method));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Core::getVerificationMethods()
{
  if (_session->status() == Status::Ready ||
      _session->status() == Status::IdentityVerificationNeeded)
    TC_RETURN(TC_AWAIT(_session->fetchVerificationMethods()));
  else
  {
    // fixme
    throw Errors::formatEx(Errors::Errc::PreconditionFailed, "");
  }
}

tc::cotask<AttachResult> Core::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  checkStatus(Status::Ready, attachProvisionalIdentity);
  TC_RETURN(TC_AWAIT(_session->attachProvisionalIdentity(sidentity)));
}

tc::cotask<void> Core::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  checkStatus(Status::Ready, verifyProvisionalIdentity);
  TC_AWAIT(_session->verifyProvisionalIdentity(verification));
}

tc::cotask<void> Core::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  checkStatus(Status::Ready, revokeDevice);
  TC_AWAIT(_session->revokeDevice(deviceId));
}

tc::cotask<Streams::EncryptionStream> Core::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& suserIds,
    std::vector<SGroupId> const& sgroupIds)
{
  checkStatus(Status::Ready, makeEncryptionStream);
  TC_RETURN(TC_AWAIT(
      _session->makeEncryptionStream(std::move(cb), suserIds, sgroupIds)));
}

tc::cotask<Streams::DecryptionStreamAdapter> Core::makeDecryptionStream(
    Streams::InputSource cb)
{
  checkStatus(Status::Ready, makeDecryptionStream);
  TC_RETURN(TC_AWAIT(_session->makeDecryptionStream(std::move(cb))));
}

tc::cotask<EncryptionSession> Core::makeEncryptionSession(
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  checkStatus(Status::Ready, makeEncryptionSession);
  TC_RETURN(
      TC_AWAIT(_session->makeEncryptionSession(publicIdentities, groupIds)));
}

Trustchain::ResourceId Core::getResourceId(
    gsl::span<uint8_t const> encryptedData)
{
  return Encryptor::extractResourceId(encryptedData);
}

tc::cotask<void> Core::nukeDatabase()
{
  checkStatus(Status::Ready, nukeDatabase);
  _session->nukeDatabase();
}
}
