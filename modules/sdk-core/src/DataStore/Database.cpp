#include <Tanker/DataStore/Database.hpp>

#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/DbModels/DeviceKeyStore.hpp>
#include <Tanker/DbModels/Groups.hpp>
#include <Tanker/DbModels/ProvisionalUserKeys.hpp>
#include <Tanker/DbModels/ResourceKeys.hpp>
#include <Tanker/DbModels/TrustchainInfo.hpp>
#include <Tanker/DbModels/UserKeys.hpp>
#include <Tanker/DbModels/Version.hpp>
#include <Tanker/DbModels/Versions.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <optional>
#include <sqlpp11/insert.h>
#include <sqlpp11/select.h>
#include <sqlpp11/sqlite3/insert_or.h>

#include <algorithm>
#include <cassert>
#include <string>
#include <vector>

TLOG_CATEGORY(Database);

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker::DataStore
{
namespace
{
template <typename Row>
Users::Device rowToDevice(Row const& row)
{
  return {DataStore::extractBlob<Trustchain::DeviceId>(row.id),
          DataStore::extractBlob<Trustchain::UserId>(row.user_id),
          DataStore::extractBlob<Crypto::PublicSignatureKey>(
              row.public_signature_key),
          DataStore::extractBlob<Crypto::PublicEncryptionKey>(
              row.public_encryption_key),
          row.is_ghost_device,
          row.is_revoked};
}
}

using UserKeysTable = DbModels::user_keys::user_keys;
using TrustchainInfoTable = DbModels::trustchain_info::trustchain_info;
using ResourceKeysTable = DbModels::resource_keys::resource_keys;
using ProvisionalUserKeysTable =
    DbModels::provisional_user_keys::provisional_user_keys;
using DeviceKeysTable = DbModels::device_key_store::device_key_store;
using GroupsTable = DbModels::groups::groups;
using VersionTable = DbModels::version::version;
using OldVersionsTable = DbModels::versions::versions;

Database::Database(std::string const& dbPath,
                   std::optional<Crypto::SymmetricKey> const& userSecret,
                   bool exclusive)
  : _db(createConnection(dbPath, userSecret, exclusive))
{
}

template <typename Table>
int Database::currentTableVersion()
{
  OldVersionsTable const versions{};
  auto const rows =
      (*_db)(select(versions.version)
                 .from(versions)
                 .where(versions.name == DataStore::tableName<Table>()));
  if (rows.empty())
    return 0;
  return static_cast<int>(rows.front().version);
}

int Database::currentDatabaseVersion()
{
  if (!tableExists<VersionTable>(*_db))
    return 0;
  VersionTable const tab{};
  auto const rows = (*_db)(select(tab.db_version).from(tab).unconditionally());
  if (rows.empty())
    throw Errors::AssertionError("version table must have a single row");
  return static_cast<int>(rows.front().db_version);
}

template <typename Table>
void Database::createOrMigrateTable(int currentVersion)
{
  if (tableExists<Table>(*_db))
  {
    TINFO("Migrating table {}", tableName<Table>());
    migrateTable<Table>(*_db, currentVersion);
  }
  else
  {
    TINFO("Creating table {}", tableName<Table>());
    createTable<Table>(*_db);
  }
}

void Database::performUnifiedMigration()
{
  auto const currentVersion = currentDatabaseVersion();

  if (currentVersion < DataStore::latestVersion())
  {
    TINFO("Performing unified migration, from version {}", currentVersion);

    switch (currentVersion)
    {
    // 0 denotes that there is no table at all
    case 0:
      createTable<GroupsTable>(*_db);
      createTable<ResourceKeysTable>(*_db);
      createTable<UserKeysTable>(*_db);
      createTable<DeviceKeysTable>(*_db);
      createTable<VersionTable>(*_db);
      [[fallthrough]];
    case 3:
      createTable<TrustchainInfoTable>(*_db);
      createTable<ProvisionalUserKeysTable>(*_db);
      _db->execute("DROP TABLE IF EXISTS resource_id_to_key_publish");
      _db->execute("DROP TABLE IF EXISTS trustchain_indexes");
      [[fallthrough]];
    case 4:
      _db->execute("DROP TABLE IF EXISTS key_publishes");
      [[fallthrough]];
    case 5:
      flushAllCaches(currentVersion);
      [[fallthrough]];
    case 6:
      _db->execute("DROP TABLE IF EXISTS trustchain");
      _db->execute("DROP TABLE IF EXISTS contact_devices");
      _db->execute("DROP TABLE IF EXISTS contact_user_keys");
      _db->execute("DROP TABLE IF EXISTS groups");
      createTable<GroupsTable>(*_db);
      [[fallthrough]];
    case 7:
      if (currentVersion != 0)
      {
        // this database wasn't just created, we need to upgrade it
        _db->execute(
            "ALTER TABLE device_key_store "
            "ADD COLUMN device_initialized BOOL");
      }
      [[fallthrough]];
    case 8: {
      // We don't support migrating half-initialized devices anymore, flush
      // everything so that we fallback to IdentityVerificationNeeded.
      auto updatedRows =
          _db->execute("DELETE FROM device_key_store WHERE device_id IS NULL");
      // In older versions, we could create multiple rows in the
      // device_key_store table, remove superfluous lines
      updatedRows += _db->execute(
          "DELETE FROM device_key_store "
          "WHERE rowid NOT IN ("
          "  SELECT rowid FROM device_key_store LIMIT 1 "
          ")");
      if (updatedRows)
        flushAllCaches(currentVersion);
    }
    break;
    default:
      throw Errors::formatEx(Errc::InvalidDatabaseVersion,
                             "invalid database version: {}",
                             currentVersion);
    }

    setDatabaseVersion(DataStore::latestVersion());

    TINFO("Migration complete");
  }
}

void Database::performOldMigration()
{
  TINFO("Performing migration from old version...");
  // retrieve each table version, and perform migration
  createOrMigrateTable<GroupsTable>(currentTableVersion<GroupsTable>());
  createOrMigrateTable<ResourceKeysTable>(
      currentTableVersion<ResourceKeysTable>());
  createOrMigrateTable<UserKeysTable>(currentTableVersion<UserKeysTable>());
  createTable<VersionTable>(*_db);

  setDatabaseVersion(3);
  dropTable<OldVersionsTable>();
}

tc::cotask<void> Database::inTransaction(
    std::function<tc::cotask<void>()> const& f)
{
  TC_AWAIT(startTransaction());
  bool transaction = true;
  std::exception_ptr exc;
  try
  {
    TC_AWAIT(f());
    transaction = false;
    TC_AWAIT(commitTransaction());
  }
  catch (...)
  {
    exc = std::current_exception();
  }
  if (exc)
  {
    if (transaction)
    {
      try
      {
        TC_AWAIT(rollbackTransaction());
      }
      catch (std::exception const& e)
      {
        TERROR("Failed to rollback transaction: {}", e.what());
      }
      catch (...)
      {
        TERROR("Failed to rollback transaction: unknown error");
      }
    }
    std::rethrow_exception(exc);
  }
}

tc::cotask<void> Database::migrate()
{
  TC_AWAIT(inTransaction([&]() -> tc::cotask<void> {
    // We used to have a version per table.
    // We now have a unique version for the db.
    // To migrate from the old system, we first create/migrate tables that
    // existed in previous versions.
    // Then we drop the old multiple-versions table, and set the global version
    // to 3, which was the maximum version before.
    // Finally, calling performUnifiedMigration will create new tables.
    if (!tableExists<VersionTable>(*_db) && tableExists<OldVersionsTable>(*_db))
      performOldMigration();
    performUnifiedMigration();
    TC_RETURN();
  }));
}

void Database::setDatabaseVersion(int version)
{
  VersionTable const tab{};
  (*_db)(update(tab).set(tab.db_version = version).unconditionally());
}

void Database::flushAllCaches(int currentVersion)
{
  FUNC_TIMER(DB);
  auto const flushTable = [this](auto const& tab) {
    (*_db)(remove_from(tab).unconditionally());
  };

  // flush all tables but DeviceKeysTable
  // Order matter for foreign key constraints
  flushTable(UserKeysTable{});
  flushTable(ResourceKeysTable{});
  flushTable(ProvisionalUserKeysTable{});
  flushTable(GroupsTable{});

  {
    TrustchainInfoTable tab{};
    (*_db)(update(tab)
               .set(tab.last_index = 0,
                    tab.trustchain_public_signature_key = sqlpp::null)
               .unconditionally());
  }

  DeviceKeysTable tab{};
  if (currentVersion != 0 && currentVersion < 7)
    (*_db)(
        update(tab).set(tab.device_id = DeviceId{}.base()).unconditionally());
  else
    (*_db)(update(tab).set(tab.device_initialized = 0).unconditionally());
}

template <typename Table>
void Database::dropTable()
{
  _db->execute(fmt::format(FMT_STRING("DROP TABLE {:s}"), tableName<Table>()));
}

void Database::nuke()
{
  FUNC_TIMER(DB);
  flushAllCaches(DataStore::latestVersion());
  {
    DeviceKeysTable tab{};
    (*_db)(remove_from(tab).unconditionally());
  }
}

tc::cotask<void> Database::startTransaction()
{
  FUNC_TIMER(DB);
  _transactions.push_back(sqlpp::start_transaction(*_db));
  TC_RETURN();
}

tc::cotask<void> Database::commitTransaction()
{
  FUNC_TIMER(DB);
  assert(!_transactions.empty());
  auto t = std::move(_transactions.back());
  _transactions.pop_back();
  t.commit();
  TC_RETURN();
}

tc::cotask<void> Database::rollbackTransaction()
{
  FUNC_TIMER(DB);
  assert(!_transactions.empty());
  _transactions.pop_back();
  TC_RETURN();
}

sqlpp::sqlite3::connection* Database::connection()
{
  return _db.get();
}

tc::cotask<Database> createDatabase(
    std::string const& dbPath,
    std::optional<Crypto::SymmetricKey> const& userSecret,
    bool exclusive)
{
  FUNC_TIMER(DB);
  Database db(dbPath, userSecret, exclusive);
  TC_AWAIT(db.migrate());
  TC_RETURN(std::move(db));
}
}
