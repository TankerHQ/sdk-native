#pragma once

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Network/SdkInfo.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/ProvisionalUsers/Manager.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ResourceKeyAccessor.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
class Client;

namespace Groups
{
class IRequester;
}

namespace ProvisionalUsers
{
class IRequester;
}

namespace Users
{
class IRequester;
}

class Session
{
public:
  struct Storage
  {
    Storage(DataStore::DatabasePtr db);

    DataStore::DatabasePtr db;
    Users::LocalUserStore localUserStore;
    Groups::Store groupStore;
    ResourceKeyStore resourceKeyStore;
    ProvisionalUserKeysStore provisionalUserKeysStore;
  };

  struct Accessors
  {
    Accessors(Storage& storage,
              Users::IRequester* userRequester,
              Groups::IRequester* groupsRequester,
              ProvisionalUsers::IRequester* provisionalRequester,
              Users::LocalUserAccessor plocalUserAccessor);
    Users::LocalUserAccessor localUserAccessor;
    mutable Users::UserAccessor userAccessor;
    ProvisionalUsers::Accessor provisionalUsersAccessor;
    ProvisionalUsers::Manager provisionalUsersManager;
    Groups::Accessor groupAccessor;
    ResourceKeyAccessor resourceKeyAccessor;
  };

  Session(std::string url, Network::SdkInfo info);

  Client& client();

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

private:
  std::unique_ptr<Client> _client;

public:
  std::unique_ptr<Users::IRequester> userRequester;
  std::unique_ptr<Groups::IRequester> groupsRequester;
  std::unique_ptr<ProvisionalUsers::IRequester> provisionalRequester;

private:
  std::unique_ptr<Storage> _storage;
  std::unique_ptr<Accessors> _accessors;
  std::optional<Identity::SecretPermanentIdentity> _identity;
  Status _status;
};
}
