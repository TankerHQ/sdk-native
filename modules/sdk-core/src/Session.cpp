#include <Tanker/Session.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Verification/Requester.hpp>

#include <boost/algorithm/string/replace.hpp>

#include <fmt/format.h>

TLOG_CATEGORY("Session");

namespace Tanker
{
namespace
{
constexpr uint8_t Version = 1;

std::string getDbPath(std::string const& path, Trustchain::UserId const& userId)
{
  if (path == ":memory:")
    return path;
  return fmt::format(FMT_STRING("{:s}/{:S}"), path, userId);
}
}

Session::Storage::Storage(Crypto::SymmetricKey const& userSecret,
                          std::unique_ptr<DataStore::DataStore> pdb)
  : db(std::move(pdb)),
    localUserStore(userSecret, db.get()),
    groupStore(userSecret, db.get()),
    resourceKeyStore(userSecret, db.get()),
    provisionalUserKeysStore(userSecret, db.get())
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
    Verification::Requester(httpClient)
{
}

Session::~Session() = default;

Session::Session(std::unique_ptr<Network::HttpClient> httpClient,
                 DataStore::Backend* datastoreBackend)
  : _httpClient(std::move(httpClient)),
    _datastoreBackend(datastoreBackend),
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

tc::cotask<void> Session::openStorage(
    Identity::SecretPermanentIdentity const& identity,
    std::string const& dataPath,
    std::string const& cachePath)
{
  assert(!_identity && !_storage);
  _identity = identity;
  _storage = std::make_unique<Storage>(
      userSecret(),
      _datastoreBackend->open(getDbPath(dataPath, userId()),
                              getDbPath(cachePath, userId())));

  auto const key = std::string_view("version");
  auto const keySpan = gsl::make_span(key).as_span<uint8_t const>();
  auto const keys = {keySpan};

  auto const dbVersionResult = _storage->db->findCacheValues(keys);
  if (!dbVersionResult[0])
  {
    auto const valueSpan = gsl::span<uint8_t const>(&Version, 1);
    auto const keyValues = {std::pair{keySpan, valueSpan}};

    _storage->db->putCacheValues(keyValues, DataStore::OnConflict::Fail);
  }
  // dbVersionResult has one row and one column
  else if (auto const dbVersion = (*dbVersionResult[0]).at(0);
           dbVersion != Version)
  {
    throw Errors::formatEx(DataStore::Errc::InvalidDatabaseVersion,
                           "unsupported device storage version: {}",
                           static_cast<int>(dbVersion));
  }
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
