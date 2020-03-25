#include <Tanker/Session.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Network/ConnectionFactory.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Utils.hpp>

#include <boost/variant2/variant.hpp>

#include <fmt/format.h>

#include <stdexcept>
#include <utility>

using namespace Tanker::Errors;

TLOG_CATEGORY(Session);

namespace Tanker
{
namespace
{
std::string getDbPath(std::string const& writablePath,
                      Trustchain::UserId const& userId)
{
  if (writablePath == ":memory:")
    return writablePath;
  return fmt::format(TFMT("{:s}/tanker-{:S}.db"), writablePath, userId);
}
}

Session::Storage::Storage(DataStore::DatabasePtr pdb)
  : db(std::move(pdb)),
    localUserStore(db.get()),
    groupStore(db.get()),
    resourceKeyStore(db.get()),
    provisionalUserKeysStore(db.get())
{
}

Session::Accessors::Accessors(
    Storage& storage,
    Users::IRequester* userRequester,
    Groups::IRequester* groupsRequester,
    ProvisionalUsers::IRequester* provisionalRequester,
    Users::LocalUserAccessor plocalUserAccessor)
  : localUserAccessor(std::move(plocalUserAccessor)),
    userAccessor(localUserAccessor.getContext(), userRequester),
    provisionalUsersAccessor(provisionalRequester,
                             &userAccessor,
                             &localUserAccessor,
                             &storage.provisionalUserKeysStore),
    provisionalUsersManager(&localUserAccessor,
                            provisionalRequester,
                            &provisionalUsersAccessor,
                            &storage.provisionalUserKeysStore,
                            localUserAccessor.getContext().id()),
    groupAccessor(groupsRequester,
                  &userAccessor,
                  &storage.groupStore,
                  &localUserAccessor,
                  &provisionalUsersAccessor),
    resourceKeyAccessor(userRequester,
                        &localUserAccessor,
                        &groupAccessor,
                        &provisionalUsersAccessor,
                        &storage.resourceKeyStore)
{
}

Session::~Session() = default;

Session::Session(std::string url, Network::SdkInfo info)
  : _client(std::make_unique<Client>(
        Network::ConnectionFactory::create(url, std::move(info)))),
    _userRequester(std::make_unique<Users::Requester>(_client.get())),
    _groupsRequester(std::make_unique<Groups::Requester>(_client.get())),
    _provisionalRequester(
        std::make_unique<ProvisionalUsers::Requester>(_client.get())),
    _status(Status::Stopped)
{
  _client->setConnectionHandler([this]() -> tc::cotask<void> {
    if (_accessors)
    {
      TC_AWAIT(_userRequester->authenticate(
          trustchainId(),
          userId(),
          TC_AWAIT(_accessors->localUserAccessor.pull())
              .deviceKeys()
              .signatureKeyPair));
    }
  });
}

tc::cotask<void> Session::finalizeSessionOpening()
{
  TC_AWAIT(_userRequester->authenticate(
      _identity->trustchainId,
      _identity->delegation.userId,
      TC_AWAIT(_storage->localUserStore.getDeviceKeys()).signatureKeyPair));
  _accessors = std::make_unique<Session::Accessors>(
      *_storage,
      _userRequester.get(),
      _groupsRequester.get(),
      _provisionalRequester.get(),
      TC_AWAIT(Users::LocalUserAccessor::create(_identity->delegation.userId,
                                                _identity->trustchainId,
                                                _userRequester.get(),
                                                &_storage->localUserStore)));
  _status = Status::Ready;
}

tc::cotask<Status> Session::open(
    Identity::SecretPermanentIdentity const& identity,
    std::string const& writablePath)
{
  _client->start();
  _identity = identity;
  _storage = std::make_unique<Storage>(TC_AWAIT(DataStore::createDatabase(
      getDbPath(writablePath, identity.delegation.userId),
      identity.userSecret)));
  auto const deviceKeys = TC_AWAIT(_storage->localUserStore.getDeviceKeys());
  auto const [deviceExists, userExists, unused] = TC_AWAIT(
      _userRequester->userStatus(identity.trustchainId,
                                 identity.delegation.userId,
                                 deviceKeys.signatureKeyPair.publicKey));
  if (deviceExists)
    TC_AWAIT(finalizeSessionOpening());
  else if (userExists)
    _status = Status::IdentityVerificationNeeded;
  else
    _status = Status::IdentityRegistrationNeeded;
  TC_RETURN(status());
}

tc::cotask<void> Session::createDevice(Unlock::Verification const& verification)
{
  TINFO("createDevice");
  FUNC_TIMER(Proc);
  if (status() != Status::IdentityVerificationNeeded)
    throw formatEx(Errc::PreconditionFailed,
                   TFMT("invalid status {:e}, should be {:e}"),
                   status(),
                   Status::IdentityVerificationNeeded);
  auto const verificationKey = TC_AWAIT(getVerificationKey(verification));
  try
  {
    auto const deviceKeys = TC_AWAIT(_storage->localUserStore.getDeviceKeys());
    auto const ghostDeviceKeys =
        GhostDevice::create(verificationKey).toDeviceKeys();
    auto const encryptedUserKey = TC_AWAIT(_client->getLastUserKey(
        _identity->trustchainId, ghostDeviceKeys.signatureKeyPair.publicKey));
    auto const privateUserEncryptionKey =
        Crypto::sealDecrypt(encryptedUserKey.encryptedPrivateKey,
                            ghostDeviceKeys.encryptionKeyPair);
    auto const entry = Users::createNewDeviceEntry(
        _identity->trustchainId,
        encryptedUserKey.deviceId,
        Identity::makeDelegation(_identity->delegation.userId,
                                 ghostDeviceKeys.signatureKeyPair.privateKey),
        deviceKeys.signatureKeyPair.publicKey,
        deviceKeys.encryptionKeyPair.publicKey,
        Crypto::makeEncryptionKeyPair(privateUserEncryptionKey));
    TC_AWAIT(_client->pushBlock(Serialization::serialize(entry)));
    TC_AWAIT(finalizeSessionOpening());
  }
  catch (Exception const& e)
  {
    if (e.errorCode() == ServerErrc::DeviceNotFound ||
        e.errorCode() == Errc::DecryptionFailed)
      throw Exception(make_error_code(Errc::InvalidVerification), e.what());
    throw;
  }
}

tc::cotask<void> Session::createUser(Unlock::Verification const& verification)
{
  TINFO("createDevice");
  FUNC_TIMER(Proc);
  if (status() != Status::IdentityRegistrationNeeded)
  {
    throw formatEx(Errc::PreconditionFailed,
                   TFMT("invalid status {:e}, should be {:e}"),
                   status(),
                   Status::IdentityRegistrationNeeded);
  }
  auto const verificationKey =
      boost::variant2::get_if<VerificationKey>(&verification);
  auto const ghostDeviceKeys =
      verificationKey ? GhostDevice::create(*verificationKey).toDeviceKeys() :
                        DeviceKeys::create();
  auto const ghostDevice = GhostDevice::create(ghostDeviceKeys);

  auto const userKeyPair = Crypto::makeEncryptionKeyPair();
  auto const userCreationEntry =
      Users::createNewUserEntry(_identity->trustchainId,
                                _identity->delegation,
                                ghostDeviceKeys.signatureKeyPair.publicKey,
                                ghostDeviceKeys.encryptionKeyPair.publicKey,
                                userKeyPair);
  auto const deviceKeys = TC_AWAIT(_storage->localUserStore.getDeviceKeys());

  auto const firstDeviceEntry = Users::createNewDeviceEntry(
      _identity->trustchainId,
      Trustchain::DeviceId{userCreationEntry.hash()},
      Identity::makeDelegation(_identity->delegation.userId,
                               ghostDevice.privateSignatureKey),
      deviceKeys.signatureKeyPair.publicKey,
      deviceKeys.encryptionKeyPair.publicKey,
      userKeyPair);

  auto const encryptVerificationKey = Crypto::encryptAead(
      _identity->userSecret,
      gsl::make_span(ghostDevice.toVerificationKey()).as_span<uint8_t const>());

  TC_AWAIT(_client->createUser(
      *_identity,
      Serialization::serialize(userCreationEntry),
      Serialization::serialize(firstDeviceEntry),
      Unlock::makeRequest(verification, _identity->userSecret),
      encryptVerificationKey));
  TC_AWAIT(finalizeSessionOpening());
}

Trustchain::UserId const& Session::userId() const
{
  return _identity->delegation.userId;
}

Trustchain::TrustchainId const& Session::trustchainId() const
{
  return _identity->trustchainId;
}

Crypto::SymmetricKey const& Session::userSecret() const
{
  return _identity->userSecret;
}

tc::cotask<void> Session::encrypt(
    uint8_t* encryptedData,
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  auto const metadata = TC_AWAIT(Encryptor::encrypt(encryptedData, clearData));
  auto spublicIdentitiesWithUs = spublicIdentities;
  spublicIdentitiesWithUs.push_back(SPublicIdentity{
      to_string(Identity::PublicPermanentIdentity{trustchainId(), userId()})});

  TC_AWAIT(
      _storage->resourceKeyStore.putKey(metadata.resourceId, metadata.key));
  auto const& localUser = _accessors->localUserAccessor.get();
  TC_AWAIT(Share::share(_accessors->userAccessor,
                        _accessors->groupAccessor,
                        trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        *_client,
                        {{metadata.key, metadata.resourceId}},
                        spublicIdentitiesWithUs,
                        sgroupIds));
}

tc::cotask<std::vector<uint8_t>> Session::encrypt(
    gsl::span<uint8_t const> clearData,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  std::vector<uint8_t> encryptedData(
      Encryptor::encryptedSize(clearData.size()));
  TC_AWAIT(
      encrypt(encryptedData.data(), clearData, spublicIdentities, sgroupIds));
  TC_RETURN(std::move(encryptedData));
}

tc::cotask<void> Session::decrypt(uint8_t* decryptedData,
                                  gsl::span<uint8_t const> encryptedData)
{
  auto const resourceId = Encryptor::extractResourceId(encryptedData);

  auto const key = TC_AWAIT(getResourceKey(resourceId));

  TC_AWAIT(Encryptor::decrypt(decryptedData, key, encryptedData));
}

tc::cotask<std::vector<uint8_t>> Session::decrypt(
    gsl::span<uint8_t const> encryptedData)
{
  std::vector<uint8_t> decryptedData(Encryptor::decryptedSize(encryptedData));
  TC_AWAIT(decrypt(decryptedData.data(), encryptedData));

  TC_RETURN(std::move(decryptedData));
}

Trustchain::DeviceId const& Session::deviceId() const
{
  return _accessors->localUserAccessor.get().deviceId();
}

tc::cotask<std::vector<Users::Device>> Session::getDeviceList() const
{
  auto const results = TC_AWAIT(_accessors->userAccessor.pull(
      gsl::make_span(std::addressof(userId()), 1)));
  if (results.found.size() != 1)
    throw Errors::AssertionError("Did not find our userId");

  TC_RETURN(results.found.at(0).devices());
}

tc::cotask<void> Session::share(
    std::vector<SResourceId> const& sresourceIds,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  if (spublicIdentities.empty() && sgroupIds.empty())
    TC_RETURN();

  auto resourceIds = convertList(sresourceIds, [](auto&& resourceId) {
    return base64DecodeArgument<Trustchain::ResourceId>(resourceId);
  });

  auto const localUser = _accessors->localUserAccessor.get();
  TC_AWAIT(Share::share(_storage->resourceKeyStore,
                        _accessors->userAccessor,
                        _accessors->groupAccessor,
                        trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        *_client,
                        resourceIds,
                        spublicIdentities,
                        sgroupIds));
}

tc::cotask<SGroupId> Session::createGroup(
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  auto const& localUser = _accessors->localUserAccessor.get();
  auto const groupId = TC_AWAIT(Groups::Manager::create(
      _accessors->userAccessor,
      *_client,
      spublicIdentities,
      trustchainId(),
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey));
  TC_RETURN(groupId);
}

tc::cotask<void> Session::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd)
{
  auto const groupId = base64DecodeArgument<Trustchain::GroupId>(groupIdString);

  auto const& localUser = _accessors->localUserAccessor.get();
  TC_AWAIT(Groups::Manager::updateMembers(
      _accessors->userAccessor,
      *_client,
      _accessors->groupAccessor,
      groupId,
      spublicIdentitiesToAdd,
      trustchainId(),
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey));
}

tc::cotask<void> Session::setVerificationMethod(
    Unlock::Verification const& method)
{
  if (boost::variant2::holds_alternative<VerificationKey>(method))
  {
    throw formatEx(Errc::InvalidArgument,
                   "cannot call setVerificationMethod with a verification key");
  }
  else
  {
    try
    {
      TC_AWAIT(_client->setVerificationMethod(
          trustchainId(), userId(), Unlock::makeRequest(method, userSecret())));
    }
    catch (Errors::Exception const& e)
    {
      if (e.errorCode() == ServerErrc::VerificationKeyNotFound)
      {
        // the server does not send an error message
        throw Errors::Exception(make_error_code(Errc::PreconditionFailed),
                                "cannot call setVerificationMethod after a "
                                "verification key has been used");
      }
      throw;
    }
  }
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Session::fetchVerificationMethods()
{
  auto methods =
      TC_AWAIT(_client->fetchVerificationMethods(trustchainId(), userId()));
  Unlock::decryptEmailMethods(methods, userSecret());
  TC_RETURN(methods);
}

tc::cotask<VerificationKey> Session::fetchVerificationKey(
    Unlock::Verification const& verification)
{
  auto const encryptedKey = TC_AWAIT(_client->fetchVerificationKey(
      trustchainId(),
      userId(),
      Unlock::makeRequest(verification, userSecret())));
  auto const verificationKey =
      TC_AWAIT(Encryptor::decryptFallbackAead(userSecret(), encryptedKey));
  TC_RETURN(VerificationKey(verificationKey.begin(), verificationKey.end()));
}

tc::cotask<VerificationKey> Session::getVerificationKey(
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

tc::cotask<VerificationKey> Session::generateVerificationKey() const
{
  TC_RETURN(GhostDevice::create().toVerificationKey());
}

tc::cotask<AttachResult> Session::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  TC_RETURN(
      TC_AWAIT(_accessors->provisionalUsersManager.attachProvisionalIdentity(
          sidentity)));
}

tc::cotask<void> Session::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  auto const& identity =
      _accessors->provisionalUsersManager.provisionalIdentity();
  if (!identity.has_value())
    throw formatEx(Errors::Errc::PreconditionFailed,
                   "cannot call verifyProvisionalIdentity "
                   "without having called "
                   "attachProvisionalIdentity before");
  Unlock::validateVerification(verification, *identity);
  TC_AWAIT(_accessors->provisionalUsersManager.verifyProvisionalIdentity(
      Unlock::makeRequest(verification, userSecret())));
}

tc::cotask<void> Session::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  auto const& localUser = TC_AWAIT(_accessors->localUserAccessor.pull());
  TC_AWAIT(Revocation::revokeDevice(
      deviceId, trustchainId(), localUser, _accessors->userAccessor, _client));
}

tc::cotask<void> Session::nukeDatabase()
{
  TC_AWAIT(_storage->db->nuke());
}

tc::cotask<Streams::EncryptionStream> Session::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  Streams::EncryptionStream encryptor(std::move(cb));

  auto spublicIdentitiesWithUs = spublicIdentities;
  spublicIdentitiesWithUs.push_back(SPublicIdentity{
      to_string(Identity::PublicPermanentIdentity{trustchainId(), userId()})});

  TC_AWAIT(_storage->resourceKeyStore.putKey(encryptor.resourceId(),
                                             encryptor.symmetricKey()));
  auto const& localUser = TC_AWAIT(_accessors->localUserAccessor.pull());
  TC_AWAIT(Share::share(_accessors->userAccessor,
                        _accessors->groupAccessor,
                        trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        *_client,
                        {{encryptor.symmetricKey(), encryptor.resourceId()}},
                        spublicIdentitiesWithUs,
                        sgroupIds));

  TC_RETURN(std::move(encryptor));
}

tc::cotask<Crypto::SymmetricKey> Session::getResourceKey(
    Trustchain::ResourceId const& resourceId)
{
  auto const key =
      TC_AWAIT(_accessors->resourceKeyAccessor.findKey(resourceId));
  if (!key)
  {
    throw formatEx(
        Errc::InvalidArgument, "key not found for resource: {:s}", resourceId);
  }
  TC_RETURN(*key);
}

tc::cotask<Streams::DecryptionStreamAdapter> Session::makeDecryptionStream(
    Streams::InputSource cb)
{
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

tc::cotask<EncryptionSession> Session::makeEncryptionSession(
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  EncryptionSession sess;
  auto spublicIdentitiesWithUs = spublicIdentities;
  spublicIdentitiesWithUs.emplace_back(
      to_string(Identity::PublicPermanentIdentity{trustchainId(), userId()}));
  TC_AWAIT(
      _storage->resourceKeyStore.putKey(sess.resourceId(), sess.sessionKey()));

  auto const& localUser = _accessors->localUserAccessor->get();
  TC_AWAIT(Share::share(_accessors->userAccessor,
                        _accessors->groupAccessor,
                        trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        *_client,
                        {{sess.sessionKey(), sess.resourceId()}},
                        spublicIdentitiesWithUs,
                        sgroupIds));
  TC_RETURN(sess);
}
}
