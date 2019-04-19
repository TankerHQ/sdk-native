#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
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

  tc::cotask<uint64_t> getTrustchainLastIndex() override;
  tc::cotask<void> addTrustchainEntry(Entry const& Entry) override;
  tc::cotask<nonstd::optional<Entry>> findTrustchainEntry(
      Crypto::Hash const& hash) override;
  tc::cotask<nonstd::optional<Entry>> findTrustchainKeyPublish(
      Crypto::Mac const& resourceId) override;
  tc::cotask<std::vector<Entry>> getTrustchainDevicesOf(
      Trustchain::UserId const& userId) override;
  tc::cotask<Entry> getTrustchainDevice(DeviceId const& deviceId) override;

  tc::cotask<void> putContact(
      Trustchain::UserId const& userId,
      nonstd::optional<Crypto::PublicEncryptionKey> const& publicKey) override;

  tc::cotask<nonstd::optional<Crypto::PublicEncryptionKey>> findContactUserKey(
      Trustchain::UserId const& userId) override;
  tc::cotask<nonstd::optional<Trustchain::UserId>>
  findContactUserIdByPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& userPublicKey) override;
  tc::cotask<void> setContactPublicEncryptionKey(
      Trustchain::UserId const& userId,
      Crypto::PublicEncryptionKey const& userPublicKey) override;

  tc::cotask<void> putResourceKey(Crypto::Mac const& mac,
                                  Crypto::SymmetricKey const& key) override;
  tc::cotask<nonstd::optional<Crypto::SymmetricKey>> findResourceKey(
      Crypto::Mac const& mac) override;

  tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys) override;
  tc::cotask<nonstd::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) override;

  tc::cotask<nonstd::optional<DeviceKeys>> getDeviceKeys() override;
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys) override;
  tc::cotask<void> setDeviceId(DeviceId const& deviceId) override;

  tc::cotask<void> putDevice(Trustchain::UserId const& userId,
                             Device const& device) override;
  tc::cotask<nonstd::optional<Device>> findDevice(DeviceId const& id) override;
  tc::cotask<std::vector<Device>> getDevicesOf(
      Trustchain::UserId const& id) override;
  tc::cotask<nonstd::optional<Trustchain::UserId>> findDeviceUserId(
      DeviceId const& id) override;
  tc::cotask<void> updateDeviceRevokedAt(DeviceId const& id,
                                         uint64_t revokedAtBlkIndex) override;

  tc::cotask<void> putFullGroup(Group const& group) override;
  tc::cotask<void> putExternalGroup(ExternalGroup const& group) override;
  // Does nothing if the group does not exist
  tc::cotask<void> updateLastGroupBlock(GroupId const& groupId,
                                        Crypto::Hash const& lastBlockHash,
                                        uint64_t lastBlockIndex) override;
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupId(
      GroupId const& groupId) override;
  tc::cotask<nonstd::optional<ExternalGroup>> findExternalGroupByGroupId(
      GroupId const& groupId) override;
  tc::cotask<nonstd::optional<Group>> findFullGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;
  tc::cotask<nonstd::optional<ExternalGroup>>
  findExternalGroupByGroupPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& publicEncryptionKey) override;

  tc::cotask<void> nuke() override;

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
