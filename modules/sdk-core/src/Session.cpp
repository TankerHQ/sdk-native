#include <Tanker/Session.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Retry.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Streams/DecryptionStream.hpp>
#include <Tanker/Streams/PeekableInputSource.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Users/Updater.hpp>
#include <Tanker/Utils.hpp>

#include <boost/variant2/variant.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/format.h>

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
  : _userSecret(config.userSecret),
    _db(std::move(config.db)),
    _localUserAccessor(std::move(config.localUserAccessor)),
    _client(std::move(config.client)),
    _userRequester(std::move(config.userRequester)),
    _groupsRequester(std::make_unique<Groups::Requester>(_client.get())),
    _groupStore(_db.get()),
    _resourceKeyStore(_db.get()),
    _provisionalUserKeysStore(_db.get()),
    _userAccessor(_localUserAccessor->getContext(), _userRequester.get()),
    _provisionalUsersAccessor(_client.get(),
                              &_userAccessor,
                              _localUserAccessor.get(),
                              &_provisionalUserKeysStore),
    _provisionalUsersManager(_localUserAccessor.get(),
                             _client.get(),
                             &_provisionalUsersAccessor,
                             &_provisionalUserKeysStore,
                             _localUserAccessor->getContext().id()),
    _groupAccessor(_groupsRequester.get(),
                   &_userAccessor,
                   &_groupStore,
                   _localUserAccessor.get(),
                   &_provisionalUsersAccessor),
    _resourceKeyAccessor(_client.get(),
                         _localUserAccessor.get(),
                         &_groupAccessor,
                         &_provisionalUsersAccessor,
                         &_resourceKeyStore)
{
  _client->setConnectionHandler([this]() -> tc::cotask<void> {
    TC_AWAIT(_userRequester->authenticate(
        trustchainId(),
        userId(),
        TC_AWAIT(_localUserAccessor->pull()).deviceKeys().signatureKeyPair));
  });
}

UserId const& Session::userId() const
{
  return this->_localUserAccessor->get().userId();
}

Trustchain::TrustchainId const& Session::trustchainId() const
{
  return this->_localUserAccessor->getContext().id();
}

Crypto::SymmetricKey const& Session::userSecret() const
{
  return this->_userSecret;
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

  TC_AWAIT(_resourceKeyStore.putKey(metadata.resourceId, metadata.key));
  auto const& localUser = _localUserAccessor->get();
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAccessor,
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
  return _localUserAccessor->get().deviceId();
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

  auto const localUser = _localUserAccessor->get();
  TC_AWAIT(Share::share(_resourceKeyStore,
                        _userAccessor,
                        _groupAccessor,
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
  auto const& localUser = _localUserAccessor->get();
  auto const groupId = TC_AWAIT(Groups::Manager::create(
      _userAccessor,
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
  auto const groupId = base64DecodeArgument<GroupId>(groupIdString);

  auto const& localUser = _localUserAccessor->get();
  TC_AWAIT(Groups::Manager::updateMembers(
      _userAccessor,
      *_client,
      _groupAccessor,
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

tc::cotask<AttachResult> Session::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  TC_RETURN(
      TC_AWAIT(_provisionalUsersManager.attachProvisionalIdentity(sidentity)));
}

tc::cotask<void> Session::verifyProvisionalIdentity(
    Unlock::Verification const& verification)
{
  auto const& identity = _provisionalUsersManager.provisionalIdentity();
  if (!identity.has_value())
    throw formatEx(Errors::Errc::PreconditionFailed,
                   "cannot call verifyProvisionalIdentity "
                   "without having called "
                   "attachProvisionalIdentity before");
  Unlock::validateVerification(verification, *identity);
  TC_AWAIT(_provisionalUsersManager.verifyProvisionalIdentity(
      Unlock::makeRequest(verification, userSecret())));
}

tc::cotask<void> Session::revokeDevice(Trustchain::DeviceId const& deviceId)
{
  auto const& localUser = TC_AWAIT(_localUserAccessor->pull());
  TC_AWAIT(Revocation::revokeDevice(
      deviceId, trustchainId(), localUser, _userAccessor, _client));
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
      to_string(Identity::PublicPermanentIdentity{trustchainId(), userId()})});

  TC_AWAIT(_resourceKeyStore.putKey(encryptor.resourceId(),
                                    encryptor.symmetricKey()));
  auto const& localUser = TC_AWAIT(_localUserAccessor->pull());
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAccessor,
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

tc::cotask<EncryptionSession*> Session::makeEncryptionSession(
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<SGroupId> const& sgroupIds)
{
  auto sess = std::make_unique<EncryptionSession>();
  auto spublicIdentitiesWithUs = spublicIdentities;
  spublicIdentitiesWithUs.emplace_back(
      to_string(Identity::PublicPermanentIdentity{trustchainId(), userId()}));
  TC_AWAIT(_resourceKeyStore.putKey(sess->resourceId(), sess->sessionKey()));

  auto const& localUser = _localUserAccessor->get();
  TC_AWAIT(Share::share(_userAccessor,
                        _groupAccessor,
                        trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        *_client,
                        {{sess->sessionKey(), sess->resourceId()}},
                        spublicIdentitiesWithUs,
                        sgroupIds));
  TC_RETURN(sess.release());
}
}
