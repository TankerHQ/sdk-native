#include <Tanker/Session.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Share.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Verification/Requester.hpp>

#include <boost/algorithm/string/replace.hpp>

#include <fmt/format.h>

#include <filesystem>

using namespace std::string_view_literals;

TLOG_CATEGORY(Session);

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

Session::Storage::Storage(Crypto::SymmetricKey const& userSecret, std::unique_ptr<DataStore::DataStore> pdb)
  : db(std::move(pdb)),
    localUserStore(userSecret, db.get()),
    groupStore(userSecret, db.get()),
    resourceKeyStore(userSecret, db.get()),
    provisionalUserKeysStore(userSecret, db.get()),
    transparentSessionStore(userSecret, db.get())
{
}

Session::Accessors::Accessors(Storage& storage,
                              Requesters* requesters,
                              Users::LocalUserAccessor plocalUserAccessor,
                              TransparentSession::SessionShareCallback shareCallback)
  : localUserAccessor(std::move(plocalUserAccessor)),
    userAccessor(localUserAccessor.getContext(), requesters),
    provisionalUsersAccessor(requesters, &userAccessor, &localUserAccessor, &storage.provisionalUserKeysStore),
    provisionalUsersManager(&localUserAccessor,
                            requesters,
                            requesters,
                            &provisionalUsersAccessor,
                            &storage.provisionalUserKeysStore,
                            localUserAccessor.getContext().id()),
    groupAccessor(requesters, &userAccessor, &storage.groupStore, &localUserAccessor, &provisionalUsersAccessor),
    resourceKeyAccessor(
        requesters, &localUserAccessor, &groupAccessor, &provisionalUsersAccessor, &storage.resourceKeyStore),
    transparentSessionAccessor(&storage.transparentSessionStore, shareCallback)
{
}

Session::Requesters::Requesters(Network::HttpClient* httpClient)
  : Users::Requester(httpClient),
    Groups::Requester(httpClient),
    ProvisionalUsers::Requester(httpClient),
    Verification::Requester(httpClient),
    Oidc::Requester(httpClient)
{
}

Session::~Session() = default;

Session::Session(std::unique_ptr<Network::HttpClient> httpClient, DataStore::Backend* datastoreBackend)
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

namespace
{
void removeStorageFile(std::string_view path)
{
  std::error_code ec;
  auto const deleted = std::filesystem::remove(path, ec);
  if (deleted)
    TINFO("Deleted old storage {}", path);
  // Note: not found is not an error (NFINAE)
  else if (ec)
    TERROR("Failed to delete old storage {}: {}", path, ec.message());
}
}

void Session::removeOldStorage(Identity::SecretPermanentIdentity const& identity, std::string const& dataPath)
{
  // Delete the db from <2.25
  removeStorageFile(fmt::format(FMT_STRING("{:s}/tanker-{:S}.db"), dataPath, identity.delegation.userId));
  removeStorageFile(fmt::format(FMT_STRING("{:s}/tanker-{:S}.db-journal"), dataPath, identity.delegation.userId));
}

void Session::openStorage(Identity::SecretPermanentIdentity const& identity,
                          std::string const& dataPath,
                          std::string const& cachePath)
{
  assert(!_identity && !_storage);

  removeOldStorage(identity, dataPath);

  _identity = identity;
  _storage = std::make_unique<Storage>(
      userSecret(), _datastoreBackend->open(getDbPath(dataPath, userId()), getDbPath(cachePath, userId())));

  auto const key = "version"sv;
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
  else if (auto const dbVersion = (*dbVersionResult[0]).at(0); dbVersion != Version)
  {
    throw Errors::formatEx(
        DataStore::Errc::InvalidDatabaseVersion, "unsupported device storage version: {}", static_cast<int>(dbVersion));
  }
}

Session::Storage const& Session::storage() const
{
  if (!_storage)
  {
    throw Errors::formatEx(Errors::Errc::InternalError, "session storage not initialized");
  }
  return *_storage;
}

Session::Storage& Session::storage()
{
  if (!_storage)
  {
    throw Errors::formatEx(Errors::Errc::InternalError, "session storage not initialized");
  }
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

tc::cotask<void> Session::finalizeCreation(Trustchain::DeviceId const& deviceId, DeviceKeys const& deviceKeys)
{
  auto shareCallback = [&](auto const& session, auto const& users, auto const& groups) {
    TC_AWAIT(transparentSessionShareImpl(session, users, groups));
    TC_RETURN();
  };

  _httpClient->setDeviceAuthData(deviceId, deviceKeys.signatureKeyPair);
  _accessors = std::make_unique<Accessors>(
      storage(),
      &requesters(),
      TC_AWAIT(Users::LocalUserAccessor::createAndInit(
          userId(), trustchainId(), &_requesters, &storage().localUserStore, deviceKeys, deviceId)),
      shareCallback);
  setStatus(Status::Ready);
}

tc::cotask<void> Session::finalizeOpening()
{
  auto shareCallback = [&](auto const& session, auto const& users, auto const& groups) {
    TC_AWAIT(transparentSessionShareImpl(session, users, groups));
    TC_RETURN();
  };
  _accessors = std::make_unique<Accessors>(
      storage(),
      &requesters(),
      TC_AWAIT(Users::LocalUserAccessor::create(userId(), trustchainId(), &_requesters, &storage().localUserStore)),
      shareCallback);
  _httpClient->setDeviceAuthData(TC_AWAIT(storage().localUserStore.getDeviceId()),
                                 TC_AWAIT(storage().localUserStore.getDeviceKeys()).signatureKeyPair);
  setStatus(Status::Ready);
}

tc::cotask<void> Session::transparentSessionShareImpl(TransparentSession::AccessorResult const& session,
                                                      std::vector<SPublicIdentity> const& users,
                                                      std::vector<SGroupId> const& groups)
{
  auto selfIdentity = SPublicIdentity(to_string(Identity::PublicPermanentIdentity{trustchainId(), userId()}));
  if (std::find(users.begin(), users.end(), selfIdentity) != users.end())
    TC_AWAIT(storage().resourceKeyStore.putKey(session.id, session.key));

  auto const localUser = TC_AWAIT(accessors().localUserAccessor.pull());
  TC_AWAIT(Share::share(accessors().userAccessor,
                        accessors().groupAccessor,
                        trustchainId(),
                        localUser.deviceId(),
                        localUser.deviceKeys().signatureKeyPair.privateKey,
                        requesters(),
                        {{session.key, session.id}},
                        users,
                        groups));
  TC_RETURN();
}

}
