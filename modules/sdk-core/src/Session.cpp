#include <Tanker/Session.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/HttpClient.hpp>
#include <Tanker/Network/ConnectionFactory.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Unlock/Requester.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>

#include <boost/algorithm/string/replace.hpp>

#include <fmt/format.h>

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

Session::Requesters::Requesters(HttpClient* httpClient)
  : Users::Requester(httpClient),
    Groups::Requester(httpClient),
    ProvisionalUsers::Requester(httpClient),
    Unlock::Requester(httpClient)
{
}

Session::~Session() = default;

Session::Session(std::string url, Network::SdkInfo info)
  : _httpClient(std::make_unique<HttpClient>(
        fetchpp::http::url(
            // TODO remove once socket io is removed
            boost::algorithm::replace_all_copy(url, "api.", "appd.")),
        info,
        tc::get_default_executor().get_io_service().get_executor())),
    _requesters(_httpClient.get()),
    _storage(nullptr),
    _accessors(nullptr),
    _identity(std::nullopt),
    _status(Status::Stopped)
{
}

void Session::createStorage(std::string const& writablePath)
{
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

tc::cotask<void> Session::createAccessors()
{
  _accessors = std::make_unique<Accessors>(
      storage(),
      &requesters(),
      TC_AWAIT(Users::LocalUserAccessor::create(
          userId(), trustchainId(), &_requesters, &storage().localUserStore)));
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

void Session::setIdentity(Identity::SecretPermanentIdentity const& identity)
{
  assert(!_identity);
  _identity = identity;
}

Identity::SecretPermanentIdentity const& Session::identity() const
{
  assert(_identity);
  return *_identity;
}

tc::cotask<void> Session::setDeviceId(Trustchain::DeviceId const& deviceId)
{
  TC_AWAIT(storage().localUserStore.setDeviceId(deviceId));
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

tc::cotask<void> Session::authenticate()
{
  TC_AWAIT(_requesters.authenticate(
      TC_AWAIT(storage().localUserStore.getDeviceId()),
      TC_AWAIT(storage().localUserStore.getDeviceKeys()).signatureKeyPair));
}

tc::cotask<void> Session::finalizeOpening()
{
  TC_AWAIT(createAccessors());
  setStatus(Status::Ready);
}

}
