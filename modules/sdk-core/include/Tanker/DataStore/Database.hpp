#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/DataStore/Connection.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace DataStore
{
class Database
{
public:
  explicit Database(std::string const& dbPath,
                    std::optional<Crypto::SymmetricKey> const& userSecret,
                    bool exclusive);

  tc::cotask<void> migrate();
  void nuke();

  tc::cotask<void> inTransaction(std::function<tc::cotask<void>()> const& f);

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

  void flushAllCaches(int currentVersion);

  tc::cotask<void> startTransaction();
  tc::cotask<void> commitTransaction();
  tc::cotask<void> rollbackTransaction();
};

tc::cotask<Database> createDatabase(
    std::string const& dbPath,
    std::optional<Crypto::SymmetricKey> const& userSecret = std::nullopt,
    bool exclusive = true);
}
}
