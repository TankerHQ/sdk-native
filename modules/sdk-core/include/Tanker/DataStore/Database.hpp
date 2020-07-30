#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Types/ProvisionalUserKeys.hpp>

#include <Tanker/DataStore/Connection.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class RecordNotFound : public std::exception
{
public:
  RecordNotFound(std::string msg) : _msg(std::move(msg))
  {
  }

  char const* what() const noexcept override
  {
    return _msg.c_str();
  }

private:
  std::string _msg;
};

class Database
{
public:
  explicit Database(std::string const& dbPath,
                    std::optional<Crypto::SymmetricKey> const& userSecret,
                    bool exclusive);
  tc::cotask<void> migrate();

  tc::cotask<void> putUserPrivateKey(
      Crypto::EncryptionKeyPair const& userKeyPair);
  tc::cotask<void> putUserKeyPairs(
      gsl::span<Crypto::EncryptionKeyPair const> userKeyPair);
  tc::cotask<std::vector<Crypto::EncryptionKeyPair>> getUserKeyPairs();

  tc::cotask<std::optional<Crypto::PublicSignatureKey>>
  findTrustchainPublicSignatureKey();
  tc::cotask<void> setTrustchainPublicSignatureKey(
      Crypto::PublicSignatureKey const&);

  tc::cotask<void> putResourceKey(Trustchain::ResourceId const& resourceId,
                                  Crypto::SymmetricKey const& key);
  tc::cotask<std::optional<Crypto::SymmetricKey>> findResourceKey(
      Trustchain::ResourceId const& resourceId);

  tc::cotask<void> putProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey,
      ProvisionalUserKeys const& provisionalUserKeys);
  tc::cotask<std::optional<ProvisionalUserKeys>> findProvisionalUserKeys(
      Crypto::PublicSignatureKey const& appPublicSigKey,
      Crypto::PublicSignatureKey const& tankerPublicSigKey);
  tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
  findProvisionalUserKeysByAppPublicEncryptionKey(
      Crypto::PublicEncryptionKey const& appPublicEncryptionKey);

  tc::cotask<std::optional<DeviceKeys>> getDeviceKeys();
  tc::cotask<void> setDeviceKeys(DeviceKeys const& deviceKeys);
  tc::cotask<void> setDeviceInitialized();
  tc::cotask<bool> isDeviceInitialized();
  tc::cotask<void> setDeviceId(Trustchain::DeviceId const& deviceId);
  tc::cotask<std::optional<Trustchain::DeviceId>> getDeviceId();

  tc::cotask<void> nuke();

  sqlpp::sqlite3::connection* connection();

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

  tc::cotask<void> startTransaction();
  tc::cotask<void> commitTransaction();
  tc::cotask<void> rollbackTransaction();
  tc::cotask<void> inTransaction(std::function<tc::cotask<void>()> const& f);
};

tc::cotask<Database> createDatabase(
    std::string const& dbPath,
    std::optional<Crypto::SymmetricKey> const& userSecret = std::nullopt,
    bool exclusive = true);
}
}
