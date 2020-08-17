#include <Tanker/Core.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Unlock/Requester.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Utils.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/variant2/variant.hpp>

#include <fmt/format.h>

#include <stdexcept>
#include <utility>

using namespace Tanker::Errors;

TLOG_CATEGORY(Core);

namespace Tanker
{
Core::~Core() = default;

Core::Core(std::string url, SdkInfo info, std::string writablePath)
  : Core(
        [url, info] {
          return std::make_unique<HttpClient>(
              fetchpp::http::url(url),
              info,
              tc::get_default_executor().get_io_service().get_executor());
        },
        std::move(writablePath))
{
}

Core::Core(HttpClientFactory httpClientFactory, std::string writablePath)
  : _httpClientFactory(std::move(httpClientFactory)),
    _writablePath(std::move(writablePath)),
    _session(std::make_shared<Session>(_httpClientFactory()))
{
}

void Core::assertStatus(Status wanted, std::string const& action) const
{
  if (auto const s = status(); s != wanted)
    throw Errors::formatEx(Errors::Errc::PreconditionFailed,
                           FMT_STRING("invalid session status {:e} for {:s}"),
                           s,
                           action);
}

Status Core::status() const
{
  return _session->status();
}

void Core::reset()
{
  _session = std::make_shared<Session>(_httpClientFactory());
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
    if (ex.errorCode() == Errors::AppdErrc::DeviceRevoked)
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

void Core::stop()
{
  if (status() == Status::Stopped)
    return;

  reset();
  if (_sessionClosed)
    _sessionClosed();
}

tc::cotask<Status> Core::startImpl(std::string const& b64Identity)
{
  _session->setIdentity(
      Identity::extract<Identity::SecretPermanentIdentity>(b64Identity));
  _session->createStorage(_writablePath);
  auto const optPubUserEncKey =
      TC_AWAIT(_session->requesters().userStatus(_session->userId()));
  if (!optPubUserEncKey)
    _session->setStatus(Status::IdentityRegistrationNeeded);
  else if (auto const optDeviceKeys = TC_AWAIT(_session->findDeviceKeys());
           !optDeviceKeys.has_value())
    _session->setStatus(Status::IdentityVerificationNeeded);
  else
  {
    TC_AWAIT(_session->authenticate());
    TC_AWAIT(_session->finalizeOpening());
    if (_session->httpClient().isRevoked())
      throw formatEx(Errors::AppdErrc::DeviceRevoked,
                     "authentication reported that this device was revoked");
  }
  TC_RETURN(status());
}

tc::cotask<Status> Core::start(std::string const& identity)
{
  SCOPE_TIMER("core_start", Proc);
  assertStatus(Status::Stopped, "start");
  TC_RETURN(TC_AWAIT(resetOnFailure([&]() -> tc::cotask<Status> {
    TC_RETURN(TC_AWAIT(startImpl(identity)));
  })));
}

tc::cotask<void> Core::verifyIdentity(Unlock::Verification const& verification)
{
  TINFO("verifyIdentity");
  FUNC_TIMER(Proc);
  assertStatus(Status::IdentityVerificationNeeded, "verifyIdentity");
  auto const verificationKey = TC_AWAIT(getVerificationKey(verification));
  try
  {
    auto const deviceKeys = DeviceKeys::create();

    auto const ghostDeviceKeys =
        GhostDevice::create(verificationKey).toDeviceKeys();
    auto const encryptedUserKey =
        TC_AWAIT(_session->requesters().getEncryptionKey(
            _session->userId(), ghostDeviceKeys.signatureKeyPair.publicKey));
    auto const privateUserEncryptionKey =
        Crypto::sealDecrypt(encryptedUserKey.encryptedUserPrivateEncryptionKey,
                            ghostDeviceKeys.encryptionKeyPair);
    auto const action = Users::createNewDeviceAction(
        _session->trustchainId(),
        encryptedUserKey.ghostDeviceId,
        Identity::makeDelegation(_session->userId(),
                                 ghostDeviceKeys.signatureKeyPair.privateKey),
        deviceKeys.signatureKeyPair.publicKey,
        deviceKeys.encryptionKeyPair.publicKey,
        Crypto::makeEncryptionKeyPair(privateUserEncryptionKey));

    TC_AWAIT(
        _session->requesters().createDevice(Serialization::serialize(action)));
    TC_AWAIT(_session->storage().localUserStore.setDeviceKeys(deviceKeys));
    TC_AWAIT(_session->setDeviceId(Trustchain::DeviceId{action.hash()}));
    TC_AWAIT(_session->finalizeOpening());
  }
  catch (Exception const& e)
  {
    if (e.errorCode() == AppdErrc::DeviceNotFound ||
        e.errorCode() == Errc::DecryptionFailed)
      throw Exception(make_error_code(Errc::InvalidVerification), e.what());
    throw;
  }
}

tc::cotask<void> Core::registerIdentity(
    Unlock::Verification const& verification)
{
  TINFO("registerIdentity");
  FUNC_TIMER(Proc);
  assertStatus(Status::IdentityRegistrationNeeded, "registerIdentity");

  auto const verificationKey =
      boost::variant2::get_if<VerificationKey>(&verification);
  auto const ghostDeviceKeys =
      verificationKey ? GhostDevice::create(*verificationKey).toDeviceKeys() :
                        DeviceKeys::create();
  auto const ghostDevice = GhostDevice::create(ghostDeviceKeys);

  auto const userKeyPair = Crypto::makeEncryptionKeyPair();
  auto const userCreationEntry =
      Users::createNewUserAction(_session->trustchainId(),
                                 _session->identity().delegation,
                                 ghostDeviceKeys.signatureKeyPair.publicKey,
                                 ghostDeviceKeys.encryptionKeyPair.publicKey,
                                 userKeyPair);
  auto const deviceKeys = DeviceKeys::create();

  auto const firstDeviceEntry = Users::createNewDeviceAction(
      _session->trustchainId(),
      Trustchain::DeviceId{userCreationEntry.hash()},
      Identity::makeDelegation(_session->userId(),
                               ghostDevice.privateSignatureKey),
      deviceKeys.signatureKeyPair.publicKey,
      deviceKeys.encryptionKeyPair.publicKey,
      userKeyPair);

  auto const encryptVerificationKey = Crypto::encryptAead(
      _session->userSecret(),
      gsl::make_span(ghostDevice.toVerificationKey()).as_span<uint8_t const>());

  TC_AWAIT(_session->requesters().createUser(
      _session->trustchainId(),
      _session->userId(),
      Serialization::serialize(userCreationEntry),
      Serialization::serialize(firstDeviceEntry),
      Unlock::makeRequest(verification, _session->userSecret()),
      encryptVerificationKey));
  TC_AWAIT(_session->storage().localUserStore.setDeviceKeys(deviceKeys));
  TC_AWAIT(
      _session->setDeviceId(Trustchain::DeviceId{firstDeviceEntry.hash()}));
  TC_AWAIT(_session->finalizeOpening());
}

tc::cotask<void> Core::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds,
    ShareWithSelf shareWithSelf)
{
  assertStatus(Status::Ready, "encrypt");
  auto const metadata = TC_AWAIT(Encryptor::encrypt(encryptedData, clearData));
  auto spublicIdentitiesWithUs = spublicIdentities;
  if (shareWithSelf == ShareWithSelf::Yes)
  {
    spublicIdentitiesWithUs.push_back(
        SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
            _session->trustchainId(), _session->userId()})});

    TC_AWAIT(_session->storage().resourceKeyStore.putKey(metadata.resourceId,
                                                         metadata.key));
  }
  else if (spublicIdentities.empty() && sgroupIds.empty())
  {
    throw Errors::formatEx(
        Errors::Errc::InvalidArgument,
        FMT_STRING("cannot encrypt without sharing with anybody"));
  }

  auto const& localUser = _session->accessors().localUserAccessor.get();
  TC_AWAIT(Share::share(_session->accessors().userAccessor,
                        _session->accessors().groupAccessor,
                        _session->trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        _session->requesters(),
                        {{metadata.key, metadata.resourceId}},
                        spublicIdentitiesWithUs,
                        sgroupIds));
}

tc::cotask<std::vector<uint8_t>> Core::encrypt(
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds,
    ShareWithSelf shareWithSelf)
{
  assertStatus(Status::Ready, "encrypt");
  std::vector<uint8_t> encryptedData(
      Encryptor::encryptedSize(clearData.size()));
  TC_AWAIT(encrypt(encryptedData.data(),
                   clearData,
                   spublicIdentities,
                   sgroupIds,
                   shareWithSelf));
  TC_RETURN(std::move(encryptedData));
}

tc::cotask<void> Core::decrypt(uint8_t* decryptedData,
                               gsl::span<uint8_t const> encryptedData)
{
  assertStatus(Status::Ready, "decrypt");
  auto const resourceId = Encryptor::extractResourceId(encryptedData);

  auto const key = TC_AWAIT(getResourceKey(resourceId));

  TC_AWAIT(Encryptor::decrypt(decryptedData, key, encryptedData));
}

tc::cotask<std::vector<uint8_t>> Core::decrypt(
    gsl::span<uint8_t const> encryptedData)
{
  assertStatus(Status::Ready, "decrypt");
  std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));
  TC_AWAIT(decrypt(decryptedData.data(), encryptedData));

  TC_RETURN(std::move(decryptedData));
}

Trustchain::DeviceId const& Core::deviceId() const
{
  assertStatus(Status::Ready, "deviceId");
  return _session->accessors().localUserAccessor.get().deviceId();
}

tc::cotask<std::vector<Users::Device>> Core::getDeviceList() const
{
  assertStatus(Status::Ready, "getDeviceList");
  auto const results = TC_AWAIT(_session->accessors().userAccessor.pull(
      gsl::make_span(std::addressof(_session->userId()), 1)));
  if (results.found.size() != 1)
    throw Errors::AssertionError("Did not find our userId");

  TC_RETURN(results.found.at(0).devices());
}

tc::cotask<void> Core::share(
    std::vector<SResourceId> const& sresourceIds,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  assertStatus(Status::Ready, "share");
  if (spublicIdentities.empty() && sgroupIds.empty())
    TC_RETURN();

  auto resourceIds = convertList(sresourceIds, [](auto&& resourceId) {
    return base64DecodeArgument<Trustchain::ResourceId>(resourceId);
  });

  auto const localUser = _session->accessors().localUserAccessor.get();
  auto const resourceKeys =
      TC_AWAIT(_session->accessors().resourceKeyAccessor.findKeys(resourceIds));
  TC_AWAIT(Share::share(_session->accessors().userAccessor,
                        _session->accessors().groupAccessor,
                        _session->trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        _session->requesters(),
                        resourceKeys,
                        spublicIdentities,
                        sgroupIds));
}

tc::cotask<SGroupId> Core::createGroup(
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  assertStatus(Status::Ready, "createGroup");
  auto const& localUser = _session->accessors().localUserAccessor.get();
  auto const groupId = TC_AWAIT(Groups::Manager::create(
      _session->accessors().userAccessor,
      _session->requesters(),
      spublicIdentities,
      _session->trustchainId(),
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey));
  TC_RETURN(groupId);
}

tc::cotask<void> Core::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd)
{
  assertStatus(Status::Ready, "updateGroupMembers");
  auto const groupId = base64DecodeArgument<Trustchain::GroupId>(groupIdString);

  auto const& localUser = _session->accessors().localUserAccessor.get();
  TC_AWAIT(Groups::Manager::updateMembers(
      _session->accessors().userAccessor,
      _session->requesters(),
      _session->accessors().groupAccessor,
      groupId,
      spublicIdentitiesToAdd,
      _session->trustchainId(),
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey));
}

tc::cotask<void> Core::setVerificationMethod(Unlock::Verification const& method)
{
  assertStatus(Status::Ready, "setVerificationMethod");
  if (boost::variant2::holds_alternative<VerificationKey>(method))
  {
    throw formatEx(Errc::InvalidArgument,
                   "cannot call setVerificationMethod with a verification key");
  }
  else
  {
    try
    {
      TC_AWAIT(_session->requesters().setVerificationMethod(
          _session->userId(),
          Unlock::makeRequest(method, _session->userSecret())));
    }
    catch (Errors::Exception const& e)
    {
      if (e.errorCode() == AppdErrc::VerificationKeyNotFound)
      {
        // the server does not send an error message
        throw Errors::formatEx(Errc::PreconditionFailed,
                               "Cannot call setVerificationMethod after a "
                               "verification key has been used. {}",
                               e.what());
      }
      throw;
    }
  }
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Core::getVerificationMethods()
{
  if (!(status() == Status::Ready ||
        status() == Status::IdentityVerificationNeeded))
    throw Errors::formatEx(Errors::Errc::PreconditionFailed,
                           FMT_STRING("invalid session status {:e} for {:s}"),
                           status(),
                           "getVerificationMethods");
  auto methods = TC_AWAIT(
      _session->requesters().fetchVerificationMethods(_session->userId()));
  if (methods.empty())
    methods.emplace_back(Tanker::VerificationKey{});
  else
    Unlock::decryptEmailMethods(methods, _session->userSecret());
  TC_RETURN(methods);
}

tc::cotask<VerificationKey> Core::fetchVerificationKey(
    Unlock::Verification const& verification)
{
  auto const encryptedKey =
      TC_AWAIT(_session->requesters().fetchVerificationKey(
          _session->userId(),
          Unlock::makeRequest(verification, _session->userSecret())));
  auto const verificationKey = TC_AWAIT(
      Encryptor::decryptFallbackAead(_session->userSecret(), encryptedKey));
  TC_RETURN(VerificationKey(verificationKey.begin(), verificationKey.end()));
}

tc::cotask<VerificationKey> Core::getVerificationKey(
    Unlock::Verification const& verification)
{
  using boost::variant2::get_if;
  using boost::variant2::holds_alternative;

  if (auto const verificationKey = get_if<VerificationKey>(&verification))
    TC_RETURN(*verificationKey);
  else if (holds_alternative<Unlock::EmailVerification>(verification) ||
           holds_alternative<Passphrase>(verification) ||
           holds_alternative<OidcIdToken>(verification))
    TC_RETURN(TC_AWAIT(fetchVerificationKey(verification)));
  throw AssertionError("invalid verification, unreachable code");
}

tc::cotask<VerificationKey> Core::generateVerificationKey() const
{
  assertStatus(Status::IdentityRegistrationNeeded, "generateVerificationKey");
  TC_RETURN(GhostDevice::create().toVerificationKey());
}

tc::cotask<AttachResult> Core::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  assertStatus(Status::Ready, "attachProvisionalIdentity");
  TC_RETURN(TC_AWAIT(
      _session->accessors().provisionalUsersManager.attachProvisionalIdentity(
          sidentity, _session->userSecret())));
}

tc::cotask<void> Core::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  assertStatus(Status::Ready, "verifyProvisionalIdentity");
  auto const& identity =
      _session->accessors().provisionalUsersManager.provisionalIdentity();
  if (!identity.has_value())
    throw formatEx(Errors::Errc::PreconditionFailed,
                   "cannot call verifyProvisionalIdentity "
                   "without having called "
                   "attachProvisionalIdentity before");
  Unlock::validateVerification(verification, *identity);
  TC_AWAIT(
      _session->accessors().provisionalUsersManager.verifyProvisionalIdentity(
          Unlock::makeRequest(verification, _session->userSecret())));
}

tc::cotask<void> Core::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  assertStatus(Status::Ready, "revokeDevice");
  auto const& localUser =
      TC_AWAIT(_session->accessors().localUserAccessor.pull());
  TC_AWAIT(Revocation::revokeDevice(deviceId,
                                    _session->trustchainId(),
                                    localUser,
                                    _session->accessors().userAccessor,
                                    _session->requesters()));
}

tc::cotask<void> Core::nukeDatabase()
{
  assertStatus(Status::Ready, "nukeDatabase");
  TC_AWAIT(_session->storage().db.nuke());
}

Trustchain::ResourceId Core::getResourceId(
    gsl::span<uint8_t const> encryptedData)
{
  return Encryptor::extractResourceId(encryptedData);
}

void Core::setSessionClosedHandler(SessionClosedHandler handler)
{
  _sessionClosed = std::move(handler);
}

tc::cotask<Streams::EncryptionStream> Core::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds,
    ShareWithSelf shareWithSelf)
{
  assertStatus(Status::Ready, "makeEncryptionStream");
  Streams::EncryptionStream encryptor(std::move(cb));

  auto spublicIdentitiesWithUs = spublicIdentities;
  if (shareWithSelf == ShareWithSelf::Yes)
  {
    spublicIdentitiesWithUs.push_back(
        SPublicIdentity{to_string(Identity::PublicPermanentIdentity{
            _session->trustchainId(), _session->userId()})});

    TC_AWAIT(_session->storage().resourceKeyStore.putKey(
        encryptor.resourceId(), encryptor.symmetricKey()));
  }
  else if (spublicIdentities.empty() && sgroupIds.empty())
  {
    throw Errors::formatEx(
        Errors::Errc::InvalidArgument,
        FMT_STRING("cannot encrypt without sharing with anybody"));
  }

  auto const& localUser =
      TC_AWAIT(_session->accessors().localUserAccessor.pull());
  TC_AWAIT(Share::share(_session->accessors().userAccessor,
                        _session->accessors().groupAccessor,
                        _session->trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        _session->requesters(),
                        {{encryptor.symmetricKey(), encryptor.resourceId()}},
                        spublicIdentitiesWithUs,
                        sgroupIds));

  TC_RETURN(std::move(encryptor));
}

tc::cotask<Crypto::SymmetricKey> Core::getResourceKey(
    Trustchain::ResourceId const& resourceId)
{
  auto const key =
      TC_AWAIT(_session->accessors().resourceKeyAccessor.findKey(resourceId));
  if (!key)
  {
    throw formatEx(
        Errc::InvalidArgument, "key not found for resource: {:s}", resourceId);
  }
  TC_RETURN(*key);
}

tc::cotask<Streams::DecryptionStreamAdapter> Core::makeDecryptionStream(
    Streams::InputSource cb)
{
  assertStatus(Status::Ready, "makeDecryptionStream");
  auto peekableSource = Streams::PeekableInputSource(std::move(cb));
  auto const version = TC_AWAIT(peekableSource.peek(1));
  if (version.empty())
    throw formatEx(Errc::InvalidArgument, "empty stream");
  if (version[0] == 4)
  {
    auto resourceKeyFinder = [this](Trustchain::ResourceId const& resourceId)
        -> tc::cotask<Crypto::SymmetricKey> {
      TC_RETURN(TC_AWAIT(this->getResourceKey(resourceId)));
    };

    auto streamDecryptor = TC_AWAIT(Streams::DecryptionStream::create(
        std::move(peekableSource), std::move(resourceKeyFinder)));
    TC_RETURN(Streams::DecryptionStreamAdapter(std::move(streamDecryptor),
                                               streamDecryptor.resourceId()));
  }
  else
  {
    auto encryptedData =
        TC_AWAIT(Streams::readAllStream(std::move(peekableSource)));
    auto const resourceId = Encryptor::extractResourceId(encryptedData);
    TC_RETURN(Streams::DecryptionStreamAdapter(
        Streams::bufferToInputSource(TC_AWAIT(decrypt(encryptedData))),
        resourceId));
  }
  throw AssertionError("makeDecryptionStream: unreachable code");
}

tc::cotask<EncryptionSession> Core::makeEncryptionSession(
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds,
    ShareWithSelf shareWithSelf)
{
  assertStatus(Status::Ready, "makeEncryptionSession");
  EncryptionSession sess{_session};
  auto spublicIdentitiesWithUs = spublicIdentities;
  if (shareWithSelf == ShareWithSelf::Yes)
  {
    spublicIdentitiesWithUs.emplace_back(
        to_string(Identity::PublicPermanentIdentity{_session->trustchainId(),
                                                    _session->userId()}));
    TC_AWAIT(_session->storage().resourceKeyStore.putKey(sess.resourceId(),
                                                         sess.sessionKey()));
  }
  else if (spublicIdentities.empty() && sgroupIds.empty())
  {
    throw Errors::formatEx(
        Errors::Errc::InvalidArgument,
        FMT_STRING("cannot encrypt without sharing with anybody"));
  }

  auto const& localUser = _session->accessors().localUserAccessor.get();
  TC_AWAIT(Share::share(_session->accessors().userAccessor,
                        _session->accessors().groupAccessor,
                        _session->trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        _session->requesters(),
                        {{sess.sessionKey(), sess.resourceId()}},
                        spublicIdentitiesWithUs,
                        sgroupIds));
  TC_RETURN(sess);
}

tc::cotask<void> Core::refreshUser()
{
  TC_AWAIT(_session->accessors().localUserAccessor.pull());
}
}
