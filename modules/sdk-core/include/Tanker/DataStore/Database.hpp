#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Tanker/DataStore/Connection.hpp>

namespace Tanker
{
namespace DataStore
{
class Database : public ADatabase
{
public:
  explicit Database(std::string const& dbPath,
                    nonstd::optional<Crypto::SymmetricKey> const& userSecret,
                    bool exclusive);

  tc::cotask<void> putUserPrivateKey(
      Crypto::PublicEncryptionKey const& publicKey,
      Crypto::PrivateEncryptionKey const& privateKey) override;
  tc::cotask<Crypto::EncryptionKeyPair> getUserKeyPair(
      Crypto::PublicEncryptionKey const& publicKey) override;
  tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
  getUserOptLastKeyPair() override;

  tc::cotask<nonstd::optional<uint64_t>> findTrustchainLastIndex() override;
  tc::cotask<nonstd::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey() override;
  tc::cotask<void> setTrustchainLastIndex(uint64_t) override;
  tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const&) override;
  tc::cotask<void> addTrustchainEntry(Entry const& Entry) override;
  tc::cotask<nonstd::optional<Entry>> findTrustchainEntry(
      Crypto::Hash const& hash) override;

  tc::cotask<void> putContact(
      Trustchain::UserId const& userId,
      nonstd::optional<Crypto::PublicEncryptionKey> const& publicKey) override;

  tc::cotask<void> putKeyPublishes(
      gsl::span<Trustchain::Actions::KeyPublish const>) override;
  tc::cotask<nonstd::optional<Trustchain::Actions::KeyPublish>> findKeyPublish(
      Trustchain::ResourceId const&) override;

  tc::cotask<nonstd::optional<Crypto::PublicEncryptionKey>> findContactUserKey(
      Trustchain::UserId const& userId) override;
  tc::cotask<nonstd::optional<Trustchain::UserId>>
  findContactUserIdByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& userPublicKey) override;
  tc::cotask<void> setContactPublicEncryptionKey(
      Trustchain::UserId const& userId,
      Crypto::PublicEncryptionKey const& userPublicKey) override;

  tc::cotask<void> putResourceKey(Trustchain::ResourceId const& resourceId,
                                  Crypto::SymmetricKey const& key) override;
  tc::cotask<nonstd::optional<Crypto::SymmetricKey>> findResourceKey(
      Trustchain::ResourceId const& resourceId) override;

  tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys) override;
  tc::cotask<nonstd::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) override;
  tc::cotask<nonstd::optional<Tanker::ProvisionalUserKeys>>
  findProvisionalUserKeysByAppPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& appPublicEncryptionKey) override;

  tc::cotask<nonstd::optional<DeviceKeys>> getDeviceKeys() override;
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys) override;
  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId) override;
  tc::cotask<nonstd::optional<Trustchain::DeviceId>> getDeviceId() override;

  tc::cotask<void> putDevice(Trustchain::UserId const& userId,
                             Device const& device) override;
  tc::cotask<nonstd::optional<Device>> findDevice(
      Trustchain::DeviceId const& id) override;
  tc::cotask<std::vector<Device>> getDevicesOf(
      Trustchain::UserId const& id) override;
  tc::cotask<nonstd::optional<Trustchain::UserId>> findDeviceUserId(
      Trustchain::DeviceId const& id) override;
  tc::cotask<void> updateDeviceRevokedAt(Trustchain::DeviceId const& id,
                                         uint64_t revokedAtBlkIndex) override;

  tc::cotask<void> putFullGroup(Group const& group) override;
  tc::cotask<void> putExternalGroup(ExternalGroup const& group) override;
  tc::cotask<void> putGroupProvisionalEncryptionKeys(
      Trustchain::GroupId const& groupId,
      std::vector<GroupProvisionalUser> const& provisionalUsers) override;
  // Does nothing if the group does not exist
  tc::cotask<void> updateLastGroupBlock(Trustchain::GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex) override;
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupId(
      Trustchain::GroupId const& groupId) override;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalGroupByGroupId(
      Trustchain::GroupId const& groupId) override;
  tc::cotask<std::vector<ExternalGroup>> findExternalGroupsByProvisionalUser(
      Crypto::PublicSignatureKey const& appPublicSignatureKey,
      Crypto::PublicSignatureKey const& tankerPublicSignatureKey) override;
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;
  tc::cotask<nonstd::optional<ExternalGroup>>
  findExternalGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;

  tc::cotask<void> nuke() override;

private:
  ConnPtr _db;

  std::vector<sqlpp::transaction_t<sqlpp::sqlite3::connection>> _transactions;

  template <typename Table>
  int currentTableVersion();
  template <typename Table>
  void createOrMigrateTable(int currentVersion);
  template <typename Table>
  void dropTable();

  void setDatabaseVersion(int version);

  void performUnifiedMigration();
  void performOldMigration();

  int currentDatabaseVersion();

  void migrate();
  void flushAllCaches();
  tc::cotask<std::vector<GroupProvisionalUser>> findProvisionalUsersByGroupId(
      Trustchain::GroupId const& groupId);

  tc::cotask<void> startTransaction() override;
  tc::cotask<void> commitTransaction() override;
  tc::cotask<void> rollbackTransaction() override;
};
}
}
