#pragma once

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/ITrustchainPuller.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/job.hpp>

#include <set>
#include <utility>
#include <vector>

namespace Tanker::Users
{
class ContactStore;
class UserKeyStore;
}

namespace Tanker
{
class Client;
class TrustchainStore;
class TrustchainVerifier;
struct Entry;

class TrustchainPuller : public ITrustchainPuller
{
public:
  TrustchainPuller(TrustchainPuller const&) = delete;
  TrustchainPuller(TrustchainPuller&&) = delete;
  TrustchainPuller& operator=(TrustchainPuller const&) = delete;
  TrustchainPuller& operator=(TrustchainPuller&&) = delete;

  TrustchainPuller(TrustchainStore* trustchain,
                   TrustchainVerifier* verifier,
                   DataStore::ADatabase* db,
                   Users::ContactStore* contactStore,
                   Users::UserKeyStore* userKeyStore,
                   DeviceKeyStore* deviceKeyStore,
                   Client* client,
                   Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                   Trustchain::DeviceId const& deviceId,
                   Trustchain::UserId const& userId);

  void setDeviceId(Trustchain::DeviceId const& deviceId);

  tc::shared_future<void> scheduleCatchUp(
      std::vector<Trustchain::UserId> const& extraUsers = {},
      std::vector<Trustchain::GroupId> const& extraGroups = {}) override;

  std::function<tc::cotask<void>(Trustchain::DeviceId const&)>
      receivedThisDeviceId;
  std::function<tc::cotask<void>(Entry const&)> deviceCreated;
  std::function<tc::cotask<void>(Entry const&)> deviceRevoked;
  std::function<tc::cotask<void>(Entry const&)> trustchainCreationReceived;

private:
  TrustchainStore* _trustchain;
  TrustchainVerifier* _verifier;
  DataStore::ADatabase* _db;
  Users::ContactStore* _contactStore;
  Users::UserKeyStore* _userKeyStore;
  DeviceKeyStore* _deviceKeyStore;
  Client* _client;

  Crypto::PublicSignatureKey _devicePublicSignatureKey;
  Trustchain::DeviceId _deviceId;
  Trustchain::UserId _userId;

  std::vector<Trustchain::UserId> _extraUsers;
  std::vector<Trustchain::GroupId> _extraGroups;
  tc::job _pullJob;

  tc::cotask<void> catchUp();
  tc::cotask<std::set<Crypto::Hash>> doInitialProcess(
      std::vector<Trustchain::ServerEntry> const& entries);
  tc::cotask<void> verifyAndAddEntry(
      Trustchain::ServerEntry const& serverEntry);
  tc::cotask<void> triggerSignals(Entry const& entry);
  tc::cotask<void> recoverUserKeys(
      std::vector<std::pair<Crypto::PublicEncryptionKey,
                            Crypto::SealedPrivateEncryptionKey>> const&
          encryptedUserKeys,
      std::vector<Crypto::EncryptionKeyPair>& userEncryptionKeys);
};
}
