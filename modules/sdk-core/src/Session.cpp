#include <Tanker/Session.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Groups/Updater.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ReceiveKey.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Retry.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Users/Updater.hpp>
#include <Tanker/Utils.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <boost/variant2/variant.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url_unpadded.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <tconcurrent/async_wait.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>
#include <tconcurrent/when.hpp>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <stdexcept>
#include <utility>

using Tanker::Trustchain::GroupId;
using Tanker::Trustchain::ResourceId;
using Tanker::Trustchain::UserId;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

TLOG_CATEGORY(Session);

namespace Tanker
{
Session::Session(Config&& config)
  : _trustchainId(config.trustchainId),
    _db(std::move(config.db)),
    _localUser(std::move(config.localUser)),
    _client(std::move(config.client)),
    _userRequester(std::move(config.userRequester)),
    _groupsRequester(std::make_unique<Groups::Requester>(_client.get())),
    _trustchain(_db.get()),
    _contactStore(std::move(config.contactStore)),
    _groupStore(_db.get()),
    _resourceKeyStore(_db.get()),
    _provisionalUserKeysStore(_db.get()),
    _userAccessor(_trustchainId,
                  _localUser->trustchainPublicSignatureKey(),
                  _userRequester.get(),
                  _contactStore.get()),
    _provisionalUsersAccessor(_client.get(),
                              _contactStore.get(),
                              _localUser.get(),
                              &_provisionalUserKeysStore),
    _provisionalUsersManager(_localUser.get(),
                             _client.get(),
                             &_provisionalUsersAccessor,
                             &_provisionalUserKeysStore,
                             _trustchainId),
    _groupAccessor(_groupsRequester.get(),
                   &_userAccessor,
                   &_groupStore,
                   _localUser.get(),
                   &_provisionalUsersAccessor),
    _resourceKeyAccessor(_client.get(),
                         _localUser.get(),
                         &_groupAccessor,
                         &_provisionalUsersAccessor,
                         &_resourceKeyStore)
{
  _client->setConnectionHandler([this]() -> tc::cotask<void> {
    TC_AWAIT(_userRequester->authenticate(
        trustchainId(), userId(), _localUser->deviceKeys().signatureKeyPair));
  });
}

UserId const& Session::userId() const
{
  return this->_localUser->userId();
}

Trustchain::TrustchainId const& Session::trustchainId() const
{
  return this->_trustchainId;
}

Crypto::SymmetricKey const& Session::userSecret() const
{
  return this->_localUser->userSecret();
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
      to_string(Identity::PublicPermanentIdentity{_trustchainId, userId()})});

  TC_AWAIT(_resourceKeyStore.putKey(metadata.resourceId, metadata.key));
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAccessor,
                        _trustchainId,
                        _localUser->deviceId(),
                        _localUser->deviceKeys().signatureKeyPair.privateKey,
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
  return _localUser->deviceId();
}

tc::cotask<std::vector<Users::Device>> Session::getDeviceList() const
{
  auto const results =
      TC_AWAIT(_userAccessor.pull(gsl::make_span(std::addressof(userId()), 1)));
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
    return base64DecodeArgument<ResourceId>(resourceId);
  });

  TC_AWAIT(Share::share(_resourceKeyStore,
                        _userAccessor,
                        _groupAccessor,
                        _trustchainId,
                        _localUser->deviceId(),
                        _localUser->deviceKeys().signatureKeyPair.privateKey,
                        *_client,
                        resourceIds,
                        spublicIdentities,
                        sgroupIds));
}

tc::cotask<SGroupId> Session::createGroup(
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  auto const groupId = TC_AWAIT(Groups::Manager::create(
      _userAccessor,
      *_client,
      spublicIdentities,
      _trustchainId,
      _localUser->deviceId(),
      _localUser->deviceKeys().signatureKeyPair.privateKey));
  TC_RETURN(groupId);
}

tc::cotask<void> Session::updateGroupMembers(
    SGroupId const& groupIdString,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd)
{
  auto const groupId = base64DecodeArgument<GroupId>(groupIdString);

  TC_AWAIT(Groups::Manager::updateMembers(
      _userAccessor,
      *_client,
      _groupAccessor,
      groupId,
      spublicIdentitiesToAdd,
      _trustchainId,
      _localUser->deviceId(),
      _localUser->deviceKeys().signatureKeyPair.privateKey));
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
          trustchainId(), userId(), method, userSecret()));
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
  TC_RETURN(TC_AWAIT(_client->fetchVerificationMethods(
      _trustchainId, userId(), userSecret())));
}

tc::cotask<AttachResult> Session::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  TC_RETURN(TC_AWAIT(_provisionalUsersManager.attachProvisionalIdentity(
      TC_AWAIT(_localUser->currentKeyPair()), sidentity)));
}

tc::cotask<void> Session::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  TC_AWAIT(_provisionalUsersManager.verifyProvisionalIdentity(
      TC_AWAIT(_localUser->currentKeyPair()), verification));
}

tc::cotask<void> Session::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  auto const serverEntries = TC_AWAIT(_userRequester->getMe());
  TC_AWAIT(Users::Updater::updateLocalUser(
      serverEntries, trustchainId(), *_localUser, *_contactStore));
  TC_AWAIT(Revocation::revokeDevice(
      deviceId, _trustchainId, *_localUser, *_contactStore, _client));
}

tc::cotask<void> Session::nukeDatabase()
{
  TC_AWAIT(_db->nuke());
}

tc::cotask<Streams::EncryptionStream> Session::makeEncryptionStream(
    Streams::InputSource cb,
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  Streams::EncryptionStream encryptor(std::move(cb));

  auto spublicIdentitiesWithUs = spublicIdentities;
  spublicIdentitiesWithUs.push_back(SPublicIdentity{
      to_string(Identity::PublicPermanentIdentity{_trustchainId, userId()})});

  TC_AWAIT(_resourceKeyStore.putKey(encryptor.resourceId(),
                                    encryptor.symmetricKey()));
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAccessor,
                        _trustchainId,
                        _localUser->deviceId(),
                        _localUser->deviceKeys().signatureKeyPair.privateKey,
                        *_client,
                        {{encryptor.symmetricKey(), encryptor.resourceId()}},
                        spublicIdentitiesWithUs,
                        sgroupIds));

  TC_RETURN(std::move(encryptor));
}

tc::cotask<Crypto::SymmetricKey> Session::getResourceKey(
    Trustchain::ResourceId const& resourceId)
{

  auto const key = TC_AWAIT(_resourceKeyAccessor.findKey(resourceId));
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
}
