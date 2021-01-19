#pragma once

#include <Tanker/DataStore/Database.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/Requester.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/HttpClient.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/ProvisionalUsers/Manager.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/Requester.hpp>
#include <Tanker/ResourceKeys/Accessor.hpp>
#include <Tanker/SdkInfo.hpp>
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
class Session
{
public:
  struct Requesters : Users::Requester,
                      Groups::Requester,
                      ProvisionalUsers::Requester,
                      Unlock::Requester

  {
    Requesters(HttpClient*);
  };

  struct Storage
  {
    Storage(DataStore::Database db);

    DataStore::Database db;
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

  Session(std::unique_ptr<HttpClient> client);
  ~Session();

  tc::cotask<void> stop();

  HttpClient& httpClient();

  Requesters const& requesters() const;
  Requesters& requesters();

  void openStorage(Identity::SecretPermanentIdentity const& identity,
                   std::string const& writablePath);
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

  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId);

  tc::cotask<std::optional<DeviceKeys>> findDeviceKeys() const;

  tc::cotask<HttpClient::AuthResponse> authenticate();
  tc::cotask<void> finalizeOpening();

private:
  std::unique_ptr<HttpClient> _httpClient;
  Requesters _requesters;
  std::unique_ptr<Storage> _storage;
  std::unique_ptr<Accessors> _accessors;
  std::optional<Identity::SecretPermanentIdentity> _identity;
  Status _status;
};
}
