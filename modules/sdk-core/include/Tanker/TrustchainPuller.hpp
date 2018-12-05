#pragma once

#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/GroupId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/job.hpp>

namespace Tanker
{
class Client;
class Trustchain;
class TrustchainVerifier;
struct Entry;
struct UnverifiedEntry;

class TrustchainPuller
{
public:
  TrustchainPuller(TrustchainPuller const&) = delete;
  TrustchainPuller(TrustchainPuller&&) = delete;
  TrustchainPuller& operator=(TrustchainPuller const&) = delete;
  TrustchainPuller& operator=(TrustchainPuller&&) = delete;

  TrustchainPuller(Trustchain* trustchain,
                   TrustchainVerifier* verifier,
                   DataStore::Database* db,
                   ContactStore* contactStore,
                   UserKeyStore* userKeyStore,
                   DeviceKeyStore* deviceKeyStore,
                   Client* client,
                   Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                   DeviceId const& deviceId,
                   UserId const& userId);

  void setDeviceId(DeviceId const& deviceId);

  tc::shared_future<void> scheduleCatchUp(
      std::vector<UserId> const& extraUsers = {},
      std::vector<GroupId> const& extraGroups = {});

  std::function<tc::cotask<void>(DeviceId const&)> receivedThisDeviceId;
  std::function<tc::cotask<void>(Entry const&)> receivedKeyToDevice;
  std::function<void(Entry const&)> receivedKeyToUser;
  std::function<void(Entry const&)> receivedKeyToUserGroup;
  std::function<tc::cotask<void>(Entry const&)> deviceCreated;
  std::function<tc::cotask<void>(Entry const&)> userGroupActionReceived;
  std::function<tc::cotask<void>(Entry const&)> deviceRevoked;

private:
  Trustchain* _trustchain;
  TrustchainVerifier* _verifier;
  DataStore::Database* _db;
  ContactStore* _contactStore;
  UserKeyStore* _userKeyStore;
  DeviceKeyStore* _deviceKeyStore;
  Client* _client;

  Crypto::PublicSignatureKey _devicePublicSignatureKey;
  DeviceId _deviceId;
  UserId _userId;

  std::vector<UserId> _extraUsers;
  std::vector<GroupId> _extraGroups;
  tc::job _pullJob;

  tc::cotask<void> catchUp();
  tc::cotask<void> verifyAndAddEntry(UnverifiedEntry const& unverifiedEntry);
  tc::cotask<void> triggerSignals(Entry const& entry);
  tc::cotask<void> recoverUserKeys(
      std::vector<UserKeyPair> const& encryptedUserKeys,
      std::vector<Crypto::EncryptionKeyPair>& userEncryptionKeys);
};
}
