#include <Tanker/Session.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Unlock/Requester.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>

#include <boost/algorithm/string/replace.hpp>

#include <fmt/format.h>

TLOG_CATEGORY("Session");

namespace Tanker
{
namespace
{
std::string getDbPath(std::string const& writablePath,
                      Trustchain::UserId const& userId)
{
  if (writablePath == ":memory:")
    return writablePath;
  return fmt::format(FMT_STRING("{:s}/tanker-{:S}.db"), writablePath, userId);
}
}

Session::Storage::Storage(DataStore::Database pdb)
  : db(std::move(pdb)),
    localUserStore(&db),
    groupStore(&db),
    resourceKeyStore(&db),
    provisionalUserKeysStore(&db)
{
}

Session::Accessors::Accessors(Storage& storage,
                              Requesters* requesters,
                              Users::LocalUserAccessor plocalUserAccessor)
  : localUserAccessor(std::move(plocalUserAccessor)),
    userAccessor(localUserAccessor.getContext(), requesters),
    provisionalUsersAccessor(requesters,
                             &userAccessor,
                             &localUserAccessor,
                             &storage.provisionalUserKeysStore),
    provisionalUsersManager(&localUserAccessor,
                            requesters,
                            requesters,
                            &provisionalUsersAccessor,
                            &storage.provisionalUserKeysStore,
                            localUserAccessor.getContext().id()),
    groupAccessor(requesters,
                  &userAccessor,
                  &storage.groupStore,
                  &localUserAccessor,
                  &provisionalUsersAccessor),
    resourceKeyAccessor(requesters,
                        &localUserAccessor,
                        &groupAccessor,
                        &provisionalUsersAccessor,
                        &storage.resourceKeyStore)
{
}

Session::Requesters::Requesters(Network::HttpClient* httpClient)
  : Users::Requester(httpClient),
    Groups::Requester(httpClient),
    ProvisionalUsers::Requester(httpClient),
    Unlock::Requester(httpClient)
{
}

Session::~Session() = default;

Session::Session(std::unique_ptr<Network::HttpClient> httpClient)
  : _httpClient(std::move(httpClient)),
    _requesters(_httpClient.get()),
    _storage(nullptr),
    _accessors(nullptr),
    _identity(std::nullopt),
    _status(Status::Stopped)
{
}

tc::cotask<void> Session::stop()
{
  TC_AWAIT(_httpClient->deauthenticate());
}

Network::HttpClient& Session::httpClient()
{
  return *_httpClient;
}

void Session::openStorage(Identity::SecretPermanentIdentity const& identity,
                          std::string const& writablePath)
{
  assert(!_identity && !_storage);
  _identity = identity;
  _storage = std::make_unique<Storage>(TC_AWAIT(DataStore::createDatabase(
      getDbPath(writablePath, userId()), userSecret())));
}

Session::Storage const& Session::storage() const
{
  assert(_storage);
  return *_storage;
}

Session::Storage& Session::storage()
{
  assert(_storage);
  return *_storage;
}

Session::Requesters const& Session::requesters() const
{
  return _requesters;
}

Session::Requesters& Session::requesters()
{
  return _requesters;
}

Session::Accessors const& Session::accessors() const
{
  assert(_accessors);
  return *_accessors;
}

Session::Accessors& Session::accessors()
{
  assert(_accessors);
  return *_accessors;
}

Identity::SecretPermanentIdentity const& Session::identity() const
{
  assert(_identity);
  return *_identity;
}

Trustchain::TrustchainId const& Session::trustchainId() const
{
  return identity().trustchainId;
}

Trustchain::UserId const& Session::userId() const
{
  return identity().delegation.userId;
}

Crypto::SymmetricKey const& Session::userSecret() const
{
  return identity().userSecret;
}

Status Session::status() const
{
  return _status;
}

void Session::setStatus(Status s)
{
  _status = s;
}

tc::cotask<std::optional<DeviceKeys>> Session::findDeviceKeys() const
{
  TC_RETURN(TC_AWAIT(storage().localUserStore.findDeviceKeys()));
}

tc::cotask<Network::HttpClient::AuthResponse> Session::authenticate()
{
  _httpClient->setDeviceAuthData(
      TC_AWAIT(storage().localUserStore.getDeviceId()),
      TC_AWAIT(storage().localUserStore.getDeviceKeys()).signatureKeyPair);
  TC_RETURN(TC_AWAIT(_httpClient->authenticate()));
}

tc::cotask<void> Session::finalizeCreation(Trustchain::DeviceId const& deviceId,
                                           DeviceKeys const& deviceKeys)
{
  _httpClient->setDeviceAuthData(deviceId, deviceKeys.signatureKeyPair);
  _accessors = std::make_unique<Accessors>(
      storage(),
      &requesters(),
      TC_AWAIT(
          Users::LocalUserAccessor::createAndInit(userId(),
                                                  trustchainId(),
                                                  &_requesters,
                                                  &storage().localUserStore,
                                                  deviceKeys,
                                                  deviceId)));
  setStatus(Status::Ready);
}

tc::cotask<void> Session::finalizeOpening()
{
  _accessors = std::make_unique<Accessors>(
      storage(),
      &requesters(),
      TC_AWAIT(Users::LocalUserAccessor::create(
          userId(), trustchainId(), &_requesters, &storage().localUserStore)));
  setStatus(Status::Ready);
}

}
