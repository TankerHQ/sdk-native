#include <Tanker/Session.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Groups/Manager.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Network/ConnectionFactory.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Unlock/Requester.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>

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

Session::Accessors::Accessors(Storage& storage,
                              Pusher* pusher,
                              Requesters* requesters,
                              Users::LocalUserAccessor plocalUserAccessor)
  : localUserAccessor(std::move(plocalUserAccessor)),
    userAccessor(localUserAccessor.getContext(), requesters),
    provisionalUsersAccessor(requesters,
                             &userAccessor,
                             &localUserAccessor,
                             &storage.provisionalUserKeysStore),
    provisionalUsersManager(&localUserAccessor,
                            pusher,
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

Session::Requesters::Requesters(Client* client)
  : Users::Requester(client),
    Groups::Requester(client),
    ProvisionalUsers::Requester(client),
    Unlock::Requester(client)
{
}

Client& Session::client()
{
  return *_client;
}

Session::Session(std::string url, Network::SdkInfo info)
  : _client(std::make_unique<Client>(
        Network::ConnectionFactory::create(std::move(url), std::move(info)))),
    _pusher(_client.get()),
    _requesters(_client.get()),
    _storage(nullptr),
    _accessors(nullptr),
    _identity(std::nullopt),
    _status(Status::Stopped)
{
  _client->setConnectionHandler([this]() -> tc::cotask<void> {
    _taskCanceler.add(tc::async_resumable(
        [this]() -> tc::cotask<void> { TC_AWAIT(authenticate()); }));
  });
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

Pusher& Session::pusher()
{
  return _pusher;
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
      &pusher(),
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

tc::cotask<DeviceKeys> Session::getDeviceKeys()
{
  TC_RETURN(TC_AWAIT(storage().localUserStore.getDeviceKeys()));
}

tc::cotask<void> Session::authenticate()
{
  TC_AWAIT(_requesters.authenticate(
      trustchainId(),
      userId(),
      TC_AWAIT(storage().localUserStore.getDeviceKeys()).signatureKeyPair));
}

tc::cotask<void> Session::finalizeOpening()
{
  TC_AWAIT(authenticate());
  TC_AWAIT(createAccessors());
  setStatus(Status::Ready);
}

}
