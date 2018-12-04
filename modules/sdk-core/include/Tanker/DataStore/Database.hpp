#pragma once

#include <Tanker/DataStore/ADatabase.hpp>

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

  tc::cotask<uint64_t> getTrustchainLastIndex() override;
  tc::cotask<void> addTrustchainEntry(Entry const& Entry) override;
  tc::cotask<nonstd::optional<Entry>> findTrustchainEntry(
      Crypto::Hash const& hash) const override;
  tc::cotask<nonstd::optional<Entry>> findTrustchainKeyPublish(
      Crypto::Mac const& resourceId) override;
  tc::cotask<std::vector<Entry>> getTrustchainDevicesOf(
      UserId const& userId) override;
  tc::cotask<Entry> getTrustchainDevice(DeviceId const& deviceId) override;

  tc::cotask<void> putContact(
      UserId const& userId,
      nonstd::optional<Crypto::PublicEncryptionKey> const& publicKey) override;

  tc::cotask<nonstd::optional<Crypto::PublicEncryptionKey>> getContactUserKey(
      UserId const& userId) override;

  tc::cotask<void> putResourceKey(Crypto::Mac const& mac,
                                  Crypto::SymmetricKey const& key) override;
  tc::cotask<nonstd::optional<Crypto::SymmetricKey>> findResourceKey(
      Crypto::Mac const& mac) override;

  tc::cotask<nonstd::optional<DeviceKeys>> getDeviceKeys() override;
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys) override;
  tc::cotask<void> setDeviceId(DeviceId const& deviceId) override;

  tc::cotask<void> putDevice(UserId const& userId,
                             Device const& device) override;
  tc::cotask<nonstd::optional<Device>> getOptDevice(
      DeviceId const& id) const override;
  tc::cotask<std::vector<Device>> getDevicesOf(UserId const& id) const override;

  tc::cotask<void> putFullGroup(Group const& group) override;
  tc::cotask<void> putExternalGroup(ExternalGroup const& group) override;
  // Does nothing if the group does not exist
  tc::cotask<void> updateLastGroupBlock(GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex) override;
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupId(
      GroupId const& groupId) const override;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalGroupByGroupId(
      GroupId const& groupId) const override;
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const override;
  tc::cotask<nonstd::optional<ExternalGroup>>
  findExternalGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) const override;

private:
  ConnPtr _db;

  std::vector<sqlpp::transaction_t<sqlpp::sqlite3::connection>> _transactions;

  bool isMigrationNeeded();
  void flushAllCaches();
  tc::cotask<void> indexKeyPublish(Crypto::Hash const& hash,
                                   Crypto::Mac const& resourceId);

  tc::cotask<void> startTransaction() override;
  tc::cotask<void> commitTransaction() override;
  tc::cotask<void> rollbackTransaction() override;
};
}
}
