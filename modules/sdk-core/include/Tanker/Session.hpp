#pragma once

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Network/SdkInfo.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/ProvisionalUsers/Manager.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/Pusher.hpp>
#include <Tanker/ResourceKeys/Accessor.hpp>
#include <Tanker/Unlock/Requester.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
class Client;

class Session
{
public:
  struct Requesters : Users::Requester,
                      Groups::Requester,
                      ProvisionalUsers::Requester,
                      Unlock::Requester

  {
    Requesters(Client*);
  };

  struct Storage
  {
    Storage(DataStore::DatabasePtr db);

    DataStore::DatabasePtr db;
    Users::LocalUserStore localUserStore;
    Groups::Store groupStore;
    ResourceKeys::Store resourceKeyStore;
    ProvisionalUserKeysStore provisionalUserKeysStore;
  };

  struct Accessors
  {
    Accessors(Storage& storage,
              Requesters* requesters,
              Users::LocalUserAccessor plocalUserAccessor);
    Users::LocalUserAccessor localUserAccessor;
    mutable Users::UserAccessor userAccessor;
    ProvisionalUsers::Accessor provisionalUsersAccessor;
    ProvisionalUsers::Manager provisionalUsersManager;
    Groups::Accessor groupAccessor;
    ResourceKeys::Accessor resourceKeyAccessor;
  };

  Session(std::string url, Network::SdkInfo info);

  Client& client();

  Pusher& pusher();

  Requesters const& requesters() const;
  Requesters& requesters();

  void createStorage(std::string const& writablePath);
  Storage const& storage() const;
  Storage& storage();

  tc::cotask<void> createAccessors();
  Accessors const& accessors() const;
  Accessors& accessors();

  Trustchain::TrustchainId const& trustchainId() const;
  Trustchain::UserId const& userId() const;
  Crypto::SymmetricKey const& userSecret() const;

  Status status() const;
  void setStatus(Status);

  Identity::SecretPermanentIdentity const& identity() const;
  void setIdentity(Identity::SecretPermanentIdentity const&);

  tc::cotask<DeviceKeys> getDeviceKeys();

  tc::cotask<void> authenticate();
  tc::cotask<void> finalizeOpening();

private:
  std::unique_ptr<Client> _client;
  Pusher _pusher;
  Requesters _requesters;
  std::unique_ptr<Storage> _storage;
  std::unique_ptr<Accessors> _accessors;
  std::optional<Identity::SecretPermanentIdentity> _identity;
  Status _status;
};
}
