#pragma once

#include <Tanker/DataStore/Backend.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/ProvisionalUsers/Manager.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/ResourceKeys/Accessor.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/TransparentSession/Accessor.hpp>
#include <Tanker/TransparentSession/Store.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/LocalUserStore.hpp>
#include <Tanker/Users/Requester.hpp>
#include <Tanker/Users/UserAccessor.hpp>
#include <Tanker/Verification/Requester.hpp>

#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
class Session
{
public:
  struct Requesters : Users::Requester, Groups::Requester, ProvisionalUsers::Requester, Verification::Requester

  {
    Requesters(Network::HttpClient*);
  };

  struct Storage
  {
    Storage(Crypto::SymmetricKey const& userSecret, std::unique_ptr<DataStore::DataStore> db);

    std::unique_ptr<DataStore::DataStore> db;
    Users::LocalUserStore localUserStore;
    Groups::Store groupStore;
    ResourceKeys::Store resourceKeyStore;
    ProvisionalUserKeysStore provisionalUserKeysStore;
    TransparentSession::Store transparentSessionStore;
  };

  struct Accessors
  {
    Accessors(Storage& storage,
              Requesters* requesters,
              Users::LocalUserAccessor plocalUserAccessor,
              TransparentSession::SessionShareCallback shareCallback);
    Users::LocalUserAccessor localUserAccessor;
    mutable Users::UserAccessor userAccessor;
    ProvisionalUsers::Accessor provisionalUsersAccessor;
    ProvisionalUsers::Manager provisionalUsersManager;
    Groups::Accessor groupAccessor;
    ResourceKeys::Accessor resourceKeyAccessor;
    TransparentSession::Accessor transparentSessionAccessor;
  };

  Session(std::unique_ptr<Network::HttpClient> client, DataStore::Backend* datastoreBackend);
  ~Session();

  tc::cotask<void> stop();

  Network::HttpClient& httpClient();

  Requesters const& requesters() const;
  Requesters& requesters();

  void openStorage(Identity::SecretPermanentIdentity const& identity,
                   std::string const& dataPath,
                   std::string const& cachePath);
  Storage const& storage() const;
  Storage& storage();

  Accessors const& accessors() const;
  Accessors& accessors();

  Trustchain::TrustchainId const& trustchainId() const;
  Trustchain::UserId const& userId() const;
  Crypto::SymmetricKey const& userSecret() const;

  Status status() const;
  void setStatus(Status);

  Identity::SecretPermanentIdentity const& identity() const;

  tc::cotask<std::optional<DeviceKeys>> findDeviceKeys() const;

  tc::cotask<void> finalizeOpening();
  tc::cotask<void> finalizeCreation(Trustchain::DeviceId const& deviceId, DeviceKeys const& deviceKeys);

private:
  std::unique_ptr<Network::HttpClient> _httpClient;
  DataStore::Backend* _datastoreBackend;
  Requesters _requesters;
  std::unique_ptr<Storage> _storage;
  std::unique_ptr<Accessors> _accessors;
  std::optional<Identity::SecretPermanentIdentity> _identity;
  Status _status;

  tc::cotask<void> transparentSessionShareImpl(TransparentSession::AccessorResult const& session,
                                               std::vector<SPublicIdentity> const& users,
                                               std::vector<SGroupId> const& groups);
  void removeOldStorage(Identity::SecretPermanentIdentity const& identity, std::string const& dataPath);
};
}
