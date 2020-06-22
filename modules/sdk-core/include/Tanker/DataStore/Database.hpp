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
                    std::optional<Crypto::SymmetricKey> const& userSecret,
                    bool exclusive);
  tc::cotask<void> migrate();

  tc::cotask<void> putUserPrivateKey(
      Crypto::EncryptionKeyPair const& userKeyPair) override;
  tc::cotask<void> putUserKeyPairs(
      gsl::span<Crypto::EncryptionKeyPair const> userKeyPair) override;
  tc::cotask<std::vector<Crypto::EncryptionKeyPair>> getUserKeyPairs() override;

  tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey() override;
  tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const&) override;

  tc::cotask<void> putResourceKey(Trustchain::ResourceId const& resourceId,
                                  Crypto::SymmetricKey const& key) override;
  tc::cotask<std::optional<Crypto::SymmetricKey>> findResourceKey(
      Trustchain::ResourceId const& resourceId) override;

  tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys) override;
  tc::cotask<std::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey) override;
  tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
  findProvisionalUserKeysByAppPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& appPublicEncryptionKey) override;

  tc::cotask<std::optional<DeviceKeys>> getDeviceKeys() override;
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys) override;
  tc::cotask<void> setDeviceInitialized() override;
  tc::cotask<bool> isDeviceInitialized() override;
  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId) override;
  tc::cotask<std::optional<Trustchain::DeviceId>> getDeviceId() override;

  tc::cotask<void> putInternalGroup(InternalGroup const& group) override;
  tc::cotask<void> putExternalGroup(ExternalGroup const& group) override;
  tc::cotask<std::optional<Group>> findGroupByGroupId(
      Trustchain::GroupId const& groupId) override;
  tc::cotask<std::optional<Group>> findGroupByGroupPublicEncryptionKey(
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

  void flushAllCaches();

  tc::cotask<void> startTransaction() override;
  tc::cotask<void> commitTransaction() override;
  tc::cotask<void> rollbackTransaction() override;
};
}
}
