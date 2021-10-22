#include <Tanker/Core.hpp>

#include <Tanker/Actions/Deduplicate.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/DeviceUnusable.hpp>
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
#include <Tanker/Trustchain/Actions/SessionCertificate.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Utils.hpp>
#include <Tanker/Verification/Requester.hpp>

#ifdef TANKER_WITH_FETCHPP
#include <Tanker/Network/FetchppBackend.hpp>
#endif
#include <Tanker/DataStore/Sqlite/Backend.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/variant2/variant.hpp>
#include <mgs/base16.hpp>
#include <mgs/base64.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <stdexcept>
#include <utility>

using namespace Tanker::Errors;

TLOG_CATEGORY(Core);

namespace Tanker
{
namespace
{
std::unique_ptr<Network::HttpClient> createHttpClient(std::string_view url,
                                                      std::string instanceId,
                                                      SdkInfo const& info,
                                                      Network::Backend* backend)
{

  auto client = std::make_unique<Network::HttpClient>(
      fmt::format("{url}/v2/apps/{appId:#S}/",
                  fmt::arg("url", url),
                  fmt::arg("appId", info.trustchainId)),
      std::move(instanceId),
      backend);
  return client;
}

std::string createInstanceId()
{
  auto rd = std::array<uint8_t, 16>{};
  Crypto::randomFill(rd);
  return mgs::base64::encode(rd);
}
}

Core::~Core() = default;

Core::Core(std::string url,
           SdkInfo info,
           std::string dataPath,
           std::string cachePath,
           std::unique_ptr<Network::Backend> networkBackend,
           std::unique_ptr<DataStore::Backend> datastoreBackend)
  : _url(std::move(url)),
    _instanceId(createInstanceId()),
    _info(std::move(info)),
    _dataPath(std::move(dataPath)),
    _cachePath(std::move(cachePath)),
    _networkBackend(networkBackend ?
                        std::move(networkBackend) :
#if TANKER_WITH_FETCHPP
                        std::make_unique<Network::FetchppBackend>(_info)
#else
                        nullptr
#endif
                        ),
    _datastoreBackend(datastoreBackend ?
                          std::move(datastoreBackend) :
                          std::make_unique<DataStore::SqliteBackend>()),
    _session(std::make_shared<Session>(
        createHttpClient(_url, _instanceId, _info, _networkBackend.get()),
        _datastoreBackend.get()))
{
  if (!_networkBackend)
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "no built-in HTTP backend, please provide one");
}

void Core::assertStatus(Status wanted, std::string const& action) const
{
  assertStatus({wanted}, action);
}

void Core::assertStatus(std::initializer_list<Status> wanted,
                        std::string const& action) const
{
  auto const actualStatus = status();
  for (auto s : wanted)
    if (actualStatus == s)
      return;

  throw Errors::formatEx(Errors::Errc::PreconditionFailed,
                         FMT_STRING("invalid session status {:e} for {:s}"),
                         actualStatus,
                         action);
}

Status Core::status() const
{
  return _session->status();
}

void Core::reset()
{
  _session = std::make_shared<Session>(
      createHttpClient(_url, _instanceId, _info, _networkBackend.get()),
      _datastoreBackend.get());
}

template <typename F>
decltype(std::declval<F>()()) Core::resetOnFailure(
    F&& f, std::vector<Errors::Errc> const& additionalErrorsToIgnore)
{
  std::exception_ptr exception;
  try
  {
    if constexpr (std::is_same_v<typename tc::detail::task_return_type<
                                     std::invoke_result_t<F>>::type,
                                 void>)
    {
      TC_AWAIT(std::forward<F>(f)());
      TC_RETURN();
    }
    else
    {
      TC_RETURN(TC_AWAIT(std::forward<F>(f)()));
    }
  }
  catch (Errors::DeviceUnusable const& ex)
  {
    // DeviceUnusable is handled at AsyncCore's level, so just ignore it here
    throw;
  }
  catch (Errors::Exception const& ex)
  {
    // DeviceRevoked is handled at AsyncCore's level, so just ignore it here
    if (ex.errorCode() == Errors::AppdErrc::DeviceRevoked)
      throw;
    for (auto const e : additionalErrorsToIgnore)
      if (ex.errorCode() == e)
        throw;
    exception = std::current_exception();
  }
  catch (tc::operation_canceled const&)
  {
    // Do not try to do anything if we are canceling operations
    throw;
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

tc::cotask<void> Core::stop()
{
  if (status() == Status::Stopped)
    TC_RETURN();

  TC_AWAIT(_session->stop());
  reset();
  if (_sessionClosed)
    _sessionClosed();
}

void Core::quickStop()
{
  // This function may be called by AsyncCore to reset everything when start()
  // fails. In these cases, we still need to call reset(), but not trigger
  // sessionClosed.
  auto const wasStopped = status() == Status::Stopped;

  // Do not stop the session, no need to close the session server-side.
  // Also, calling _session->stop() here crashes.
  reset();
  if (!wasStopped && _sessionClosed)
    _sessionClosed();
}

tc::cotask<Status> Core::startImpl(std::string const& b64Identity)
{
  auto const identity =
      Identity::extract<Identity::SecretPermanentIdentity>(b64Identity);

  if (identity.trustchainId != _info.trustchainId)
  {
    throw Errors::formatEx(
        Errors::Errc::InvalidArgument,
        "the provided identity was not signed by the private key of the "
        "current app: expected app ID {} but got {}",
        _info.trustchainId,
        identity.trustchainId);
  }
  TC_AWAIT(_session->openStorage(identity, _dataPath, _cachePath));
  auto const optPubUserEncKey =
      TC_AWAIT(_session->requesters().userStatus(_session->userId()));
  if (!optPubUserEncKey)
    _session->setStatus(Status::IdentityRegistrationNeeded);
  else if (auto const optDeviceKeys = TC_AWAIT(_session->findDeviceKeys());
           !optDeviceKeys.has_value())
    _session->setStatus(Status::IdentityVerificationNeeded);
  else
  {
    try
    {
      auto const authResponse = TC_AWAIT(_session->authenticate());
      TC_AWAIT(_session->finalizeOpening());
      if (authResponse == Network::HttpClient::AuthResponse::Revoked)
        throw formatEx(Errors::AppdErrc::DeviceRevoked,
                       "authentication reported that this device was revoked");
    }
    catch (Errors::Exception const& e)
    {
      if (e.errorCode() == Errors::AppdErrc::InvalidChallengePublicKey ||
          e.errorCode() == Errors::AppdErrc::InvalidChallengeSignature ||
          e.errorCode() == Errors::AppdErrc::DeviceNotFound)
        throw Errors::DeviceUnusable(e.what());
      else
        throw;
    }
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

tc::cotask<void> Core::registerIdentityImpl(
    Verification::Verification const& verification,
    std::optional<std::string> const& withTokenNonce)
{
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

  auto const verificationKeyToSend = ghostDevice.toVerificationKey();
  std::vector<uint8_t> encryptedVerificationKey(
      EncryptorV2::encryptedSize(verificationKeyToSend.size()));
  EncryptorV2::encryptSync(
      encryptedVerificationKey.data(),
      gsl::make_span(verificationKeyToSend).as_span<uint8_t const>(),
      _session->userSecret());

  auto const deviceId = Trustchain::DeviceId{firstDeviceEntry.hash()};

  TC_AWAIT(_session->requesters().createUser(
      _session->trustchainId(),
      _session->userId(),
      Serialization::serialize(userCreationEntry),
      Serialization::serialize(firstDeviceEntry),
      Verification::makeRequestWithVerif(
          verification, _session->userSecret(), std::nullopt, withTokenNonce),
      encryptedVerificationKey));
  TC_AWAIT(_session->finalizeCreation(deviceId, deviceKeys));
}

tc::cotask<std::optional<std::string>> Core::registerIdentity(
    Verification::Verification const& verification, VerifyWithToken withToken)
{
  FUNC_TIMER(Proc);
  assertStatus(Status::IdentityRegistrationNeeded, "registerIdentity");
  if (withToken == VerifyWithToken::Yes &&
      boost::variant2::holds_alternative<VerificationKey>(verification))
  {
    throw formatEx(Errc::InvalidArgument,
                   "cannot get a session token with a verification key");
  }
  if (boost::variant2::holds_alternative<PreverifiedEmail>(verification) ||
      boost::variant2::holds_alternative<PreverifiedPhoneNumber>(verification))
  {
    throw formatEx(Errc::InvalidArgument,
                   "cannot register identity with preverified methods");
  }
  auto withTokenNonce = makeWithTokenRandomNonce(withToken);
  TC_AWAIT(resetOnFailure(
      [&]() -> tc::cotask<void> {
        TC_AWAIT(registerIdentityImpl(verification, withTokenNonce));
      },
      {Errors::Errc::ExpiredVerification,
       Errors::Errc::InvalidVerification,
       Errors::Errc::InvalidArgument,
       Errors::Errc::PreconditionFailed,
       Errors::Errc::TooManyAttempts}));

  if (withToken == VerifyWithToken::No)
    TC_RETURN(std::nullopt);
  TC_RETURN(TC_AWAIT(getSessionToken(verification, *withTokenNonce)));
}

tc::cotask<void> Core::verifyIdentityImpl(
    Verification::Verification const& verification,
    std::optional<std::string> const& withTokenNonce)
{
  auto const verificationKey =
      TC_AWAIT(getVerificationKey(verification, withTokenNonce));
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

    auto const deviceId = Trustchain::DeviceId{action.hash()};

    TC_AWAIT(
        _session->requesters().createDevice(Serialization::serialize(action)));
    TC_AWAIT(_session->finalizeCreation(deviceId, deviceKeys));
  }
  catch (Exception const& e)
  {
    if (e.errorCode() == AppdErrc::DeviceNotFound ||
        e.errorCode() == Errc::DecryptionFailed)
      throw Exception(make_error_code(Errc::InvalidVerification), e.what());
    throw;
  }
}

tc::cotask<std::optional<std::string>> Core::verifyIdentity(
    Verification::Verification const& verification, VerifyWithToken withToken)
{
  FUNC_TIMER(Proc);
  if (withToken == VerifyWithToken::Yes)
  {
    assertStatus({Status::IdentityVerificationNeeded, Status::Ready},
                 "verifyIdentity");
    if (boost::variant2::holds_alternative<VerificationKey>(verification))
    {
      throw formatEx(Errc::InvalidArgument,
                     "cannot get a session token with a verification key");
    }
  }
  else
  {
    assertStatus(Status::IdentityVerificationNeeded, "verifyIdentity");
  }

  if (boost::variant2::holds_alternative<PreverifiedEmail>(verification) ||
      boost::variant2::holds_alternative<PreverifiedPhoneNumber>(verification))
  {
    throw formatEx(Errc::InvalidArgument,
                   "cannot verify identity with preverified methods");
  }

  auto withTokenNonce = makeWithTokenRandomNonce(withToken);
  TC_AWAIT(resetOnFailure(
      [&]() -> tc::cotask<void> {
        TC_AWAIT(verifyIdentityImpl(verification, withTokenNonce));
      },
      {Errors::Errc::ExpiredVerification,
       Errors::Errc::InvalidVerification,
       Errors::Errc::InvalidArgument,
       Errors::Errc::PreconditionFailed,
       Errors::Errc::TooManyAttempts}));

  if (withToken == VerifyWithToken::No)
    TC_RETURN(std::nullopt);
  TC_RETURN(TC_AWAIT(getSessionToken(verification, *withTokenNonce)));
}

tc::cotask<std::string> Core::getSessionToken(
    Verification::Verification const& verification,
    const std::string& withTokenNonce)
{
  assertStatus(Status::Ready, "getSessionToken");

  auto const& localUser = _session->accessors().localUserAccessor.get();
  auto sessionCertificate = Users::createSessionCertificate(
      _session->trustchainId(),
      deviceId(),
      verification,
      localUser.deviceKeys().signatureKeyPair.privateKey);
  auto const serializedSessCert = Serialization::serialize(sessionCertificate);

  TC_RETURN(TC_AWAIT(_session->requesters().getSessionToken(
      _session->userId(), serializedSessCert, withTokenNonce)));
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
  auto const results =
      TC_AWAIT(_session->accessors().userAccessor.pull({_session->userId()}));
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
  if (sresourceIds.empty() || (spublicIdentities.empty() && sgroupIds.empty()))
    TC_RETURN();

  auto const resourceIds =
      sresourceIds | ranges::views::transform([](auto&& resourceId) {
        return base64DecodeArgument<Trustchain::ResourceId>(resourceId,
                                                            "resource id");
      }) |
      ranges::to<std::vector> | Actions::deduplicate;

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
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove)
{
  assertStatus(Status::Ready, "updateGroupMembers");
  auto const groupId =
      base64DecodeArgument<Trustchain::GroupId>(groupIdString, "group id");

  auto const& localUser = _session->accessors().localUserAccessor.get();
  TC_AWAIT(Groups::Manager::updateMembers(
      _session->accessors().userAccessor,
      _session->requesters(),
      _session->accessors().groupAccessor,
      groupId,
      spublicIdentitiesToAdd,
      spublicIdentitiesToRemove,
      _session->trustchainId(),
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey));
}

tc::cotask<std::optional<std::string>> Core::setVerificationMethod(
    Verification::Verification const& method, VerifyWithToken withToken)
{
  assertStatus(Status::Ready, "setVerificationMethod");
  if (boost::variant2::holds_alternative<VerificationKey>(method))
  {
    throw formatEx(Errc::InvalidArgument,
                   "cannot call setVerificationMethod with a verification key");
  }
  auto withTokenNonce = makeWithTokenRandomNonce(withToken);

  try
  {
    TC_AWAIT(_session->requesters().setVerificationMethod(
        _session->userId(),
        Verification::makeRequestWithVerif(
            method, _session->userSecret(), std::nullopt, withTokenNonce)));
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

  if (withToken == VerifyWithToken::No)
    TC_RETURN(std::nullopt);
  TC_RETURN(TC_AWAIT(getSessionToken(method, *withTokenNonce)));
}

tc::cotask<std::vector<Verification::VerificationMethod>>
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
    TC_AWAIT(Verification::decryptMethods(methods, _session->userSecret()));
  TC_RETURN(methods);
}

tc::cotask<VerificationKey> Core::fetchVerificationKey(
    Verification::Verification const& verification,
    std::optional<std::string> const& withTokenNonce)
{
  auto const encryptedKey =
      TC_AWAIT(_session->requesters().fetchVerificationKey(
          _session->userId(),
          Verification::makeRequestWithVerif(verification,
                                             _session->userSecret(),
                                             std::nullopt,
                                             withTokenNonce)));
  std::vector<uint8_t> verificationKey(
      EncryptorV2::decryptedSize(encryptedKey));
  TC_AWAIT(EncryptorV2::decrypt(
      verificationKey.data(), _session->userSecret(), encryptedKey));
  TC_RETURN(VerificationKey(verificationKey.begin(), verificationKey.end()));
}

tc::cotask<VerificationKey> Core::getVerificationKey(
    Verification::Verification const& verification,
    std::optional<std::string> const& withTokenNonce)
{
  using boost::variant2::get_if;
  using boost::variant2::holds_alternative;

  if (auto const verificationKey = get_if<VerificationKey>(&verification))
    TC_RETURN(*verificationKey);
  else if (holds_alternative<Verification::ByEmail>(verification) ||
           holds_alternative<Verification::ByPhoneNumber>(verification) ||
           holds_alternative<Passphrase>(verification) ||
           holds_alternative<OidcIdToken>(verification))
    TC_RETURN(TC_AWAIT(fetchVerificationKey(verification, withTokenNonce)));
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
    Verification::Verification const& verification)
{
  assertStatus(Status::Ready, "verifyProvisionalIdentity");
  auto const& identity =
      _session->accessors().provisionalUsersManager.provisionalIdentity();
  if (!identity.has_value())
    throw formatEx(Errors::Errc::PreconditionFailed,
                   "cannot call verifyProvisionalIdentity "
                   "without having called "
                   "attachProvisionalIdentity before");
  Verification::validateVerification(verification, *identity);
  TC_AWAIT(
      _session->accessors().provisionalUsersManager.verifyProvisionalIdentity(
          Verification::makeRequestWithVerif(verification,
                                             _session->userSecret(),
                                             identity->appSignatureKeyPair)));
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

void Core::nukeDatabase()
{
  _session->storage().db.nuke();
  _session->storage().db2->nuke();
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

void Core::setHttpSessionToken(std::string_view token)
{
  this->_session->httpClient().setAccessToken(token);
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

std::optional<std::string> Core::makeWithTokenRandomNonce(
    VerifyWithToken wanted)
{
  if (wanted == VerifyWithToken::No)
    return std::nullopt;
  std::array<uint8_t, 8> randombuf;
  Tanker::Crypto::randomFill(gsl::make_span(randombuf));
  return mgs::base16::encode(randombuf.begin(), randombuf.end());
}

tc::cotask<void> Core::confirmRevocation()
{
  TC_AWAIT(_session->accessors().localUserAccessor.confirmRevocation());
}
}
