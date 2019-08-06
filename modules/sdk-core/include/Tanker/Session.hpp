#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/CloudStorage.hpp>
#include <Tanker/ContactStore.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/KeyPublishStore.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/StreamDecryptor.hpp>
#include <Tanker/StreamEncryptor.hpp>
#include <Tanker/StreamInputSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/TrustchainVerifier.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Methods.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/UserAccessor.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
struct Entry;
struct UnverifiedEntry;

class Session
{
public:
  struct Config
  {
    DataStore::DatabasePtr db;
    Trustchain::TrustchainId trustchainId;
    Trustchain::UserId userId;
    Crypto::SymmetricKey userSecret;
    std::unique_ptr<DeviceKeyStore> deviceKeyStore;
    std::unique_ptr<Client> client;
  };
  using DeviceRevokedHandler = std::function<void()>;

  Session(Config&&);

  tc::cotask<void> startConnection();

  Trustchain::UserId const& userId() const;
  Trustchain::TrustchainId const& trustchainId() const;
  Crypto::SymmetricKey const& userSecret() const;

  tc::cotask<void> encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData,
                           std::vector<SPublicIdentity> const& suserIds = {},
                           std::vector<SGroupId> const& sgroupIds = {});

  tc::cotask<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> share(std::vector<SResourceId> const& sresourceIds,
                         std::vector<SPublicIdentity> const& publicIdentities,
                         std::vector<SGroupId> const& groupIds);

  tc::cotask<SGroupId> createGroup(
      std::vector<SPublicIdentity> const& spublicIdentities);
  tc::cotask<void> updateGroupMembers(
      SGroupId const& groupIdString,
      std::vector<SPublicIdentity> const& spublicIdentitiesToAdd);

  tc::cotask<void> setVerificationMethod(Unlock::Verification const& method);
  tc::cotask<std::vector<Unlock::VerificationMethod>>
  fetchVerificationMethods();

  tc::cotask<AttachResult> attachProvisionalIdentity(
      SSecretProvisionalIdentity const& sidentity);
  tc::cotask<void> verifyProvisionalIdentity(
      Unlock::Verification const& verification);

  tc::cotask<void> syncTrustchain();

  tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId);

  DeviceRevokedHandler deviceRevoked;
  std::function<void(Trustchain::DeviceId const&)> gotDeviceId;

  tc::cotask<void> catchUserKey(
      Trustchain::DeviceId const& id,
      Trustchain::Actions::DeviceCreation const& deviceCreation);
  Trustchain::DeviceId const& deviceId() const;
  tc::cotask<std::vector<Device>> getDeviceList() const;

  tc::cotask<StreamEncryptor> makeStreamEncryptor(
      StreamInputSource,
      std::vector<SPublicIdentity> const& suserIds = {},
      std::vector<SGroupId> const& sgroupIds = {});

  tc::cotask<StreamDecryptor> makeStreamDecryptor(StreamInputSource);

  tc::cotask<CloudStorage::UploadTicket> getFileUploadTicket(
      Trustchain::ResourceId const& resourceId, uint64_t length);
  tc::cotask<CloudStorage::DownloadTicket> getFileDownloadTicket(
      Trustchain::ResourceId const& resourceId);

private:
  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId);
  tc::cotask<void> onKeyToDeviceReceived(Entry const& entry);
  tc::cotask<void> onDeviceCreated(Entry const& entry);
  tc::cotask<void> onDeviceRevoked(Entry const& entry);
  void onKeyToUserReceived(Entry const& entry);
  void onKeyToUserGroupReceived(Entry const& entry);
  tc::cotask<void> onUserGroupEntry(Entry const& entry);
  tc::cotask<void> onProvisionalIdentityClaimEntry(Entry const& entry);
  tc::cotask<void> onKeyPublishReceived(Entry const& entry);
  tc::cotask<void> onTrustchainCreationReceived(Entry const& entry);
  tc::cotask<Crypto::SymmetricKey> getResourceKey(
      Trustchain::ResourceId const&);

private:
  Trustchain::TrustchainId _trustchainId;
  Trustchain::UserId _userId;
  Crypto::SymmetricKey _userSecret;
  DataStore::DatabasePtr _db;
  std::unique_ptr<DeviceKeyStore> _deviceKeyStore;
  std::unique_ptr<Client> _client;
  TrustchainStore _trustchain;
  UserKeyStore _userKeyStore;
  ContactStore _contactStore;
  GroupStore _groupStore;
  ResourceKeyStore _resourceKeyStore;
  ProvisionalUserKeysStore _provisionalUserKeysStore;
  KeyPublishStore _keyPublishStore;

  TrustchainVerifier _verifier;
  TrustchainPuller _trustchainPuller;
  UserAccessor _userAccessor;
  GroupAccessor _groupAcessor;
  BlockGenerator _blockGenerator;
  nonstd::optional<Identity::SecretProvisionalIdentity> _provisionalIdentity;

  tc::promise<void> _ready;
  tc::task_auto_canceler _taskCanceler;

  tc::cotask<void> connectionHandler();
  tc::cotask<void> nukeDatabase();
};
}
