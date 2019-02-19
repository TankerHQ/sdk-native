#pragma once

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Trustchain.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/TrustchainVerifier.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Unlock/Methods.hpp>
#include <Tanker/Unlock/Options.hpp>
#include <Tanker/UserAccessor.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <boost/signals2/signal.hpp>
#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
namespace Unlock
{
struct Registration;
}

struct Entry;
struct UnverifiedEntry;

class Session
{
public:
  struct Config
  {
    DataStore::DatabasePtr db;
    TrustchainId trustchainId;
    UserId userId;
    Crypto::SymmetricKey userSecret;
    std::unique_ptr<DeviceKeyStore> deviceKeyStore;
    std::unique_ptr<Client> client;
  };

  Session(Config&&);

  tc::cotask<void> startConnection();

  UserId const& userId() const;
  TrustchainId const& trustchainId() const;
  Crypto::SymmetricKey const& userSecret() const;

  tc::cotask<void> encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData,
                           std::vector<SUserId> const& suserIds = {},
                           std::vector<SGroupId> const& sgroupIds = {});

  tc::cotask<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> share(std::vector<SResourceId> const& sresourceIds,
                         std::vector<SUserId> const& userIds,
                         std::vector<SGroupId> const& groupIds);

  tc::cotask<SGroupId> createGroup(std::vector<SUserId> stringUserIds);
  tc::cotask<void> updateGroupMembers(SGroupId const& groupIdString,
                                      std::vector<SUserId> usersToAdd);

  tc::cotask<std::unique_ptr<Unlock::Registration>> generateUnlockKey();

  tc::cotask<void> registerUnlockKey(Unlock::Registration const& registration);

  tc::cotask<void> createUnlockKey(Unlock::CreationOptions const& options);

  tc::cotask<void> updateUnlock(Unlock::UpdateOptions const& options);

  tc::cotask<void> registerUnlock(Unlock::RegistrationOptions const& options);

  tc::cotask<UnlockKey> generateAndRegisterUnlockKey();

  tc::cotask<bool> isUnlockAlreadySetUp() const;
  Unlock::Methods registeredUnlockMethods() const;
  bool hasRegisteredUnlockMethods() const;
  bool hasRegisteredUnlockMethods(Unlock::Method) const;

  tc::cotask<void> syncTrustchain();

  tc::cotask<void> revokeDevice(DeviceId const& deviceId);

  boost::signals2::signal<void()> deviceCreated;
  boost::signals2::signal<void()> deviceRevoked;

  tc::cotask<void> catchUserKey(DeviceId const& id,
                                DeviceCreation const& deviceCreation);
  DeviceId const& deviceId() const;

private:
  tc::cotask<void> share(std::vector<Crypto::Mac> const& resourceId,
                         std::vector<UserId> const& userIds,
                         std::vector<GroupId> const& groupIds);

  tc::cotask<void> setDeviceId(DeviceId const& deviceId);
  tc::cotask<void> onKeyToDeviceReceived(Entry const& entry);
  tc::cotask<void> onDeviceCreated(Entry const& entry);
  tc::cotask<void> onDeviceRevoked(Entry const& entry);
  void onKeyToUserReceived(Entry const& entry);
  void onKeyToUserGroupReceived(Entry const& entry);
  tc::cotask<void> onUserGroupEntry(Entry const& entry);
  void updateLocalUnlockMethods(Unlock::RegistrationOptions const& methods);

private:
  TrustchainId _trustchainId;
  UserId _userId;
  Crypto::SymmetricKey _userSecret;
  DataStore::DatabasePtr _db;
  std::unique_ptr<DeviceKeyStore> _deviceKeyStore;
  std::unique_ptr<Client> _client;
  Trustchain _trustchain;
  UserKeyStore _userKeyStore;
  ContactStore _contactStore;
  GroupStore _groupStore;
  ResourceKeyStore _resourceKeyStore;

  TrustchainVerifier _verifier;
  TrustchainPuller _trustchainPuller;
  UserAccessor _userAccessor;
  GroupAccessor _groupAcessor;
  BlockGenerator _blockGenerator;
  Unlock::Methods _unlockMethods;

  std::map<Crypto::Mac, tc::promise<void>> _pendingRequests;

  tc::promise<void> _ready;

  tc::cotask<void> connectionHandler();
  void signalKeyReady(Crypto::Mac const& mac);
  tc::cotask<void> nukeDatabase();
};
}
