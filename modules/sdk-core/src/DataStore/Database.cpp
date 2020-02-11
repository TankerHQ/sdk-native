#include <Tanker/DataStore/Database.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/DbModels/ContactDevices.hpp>
#include <Tanker/DbModels/ContactUserKeys.hpp>
#include <Tanker/DbModels/DeviceKeyStore.hpp>
#include <Tanker/DbModels/Groups.hpp>
#include <Tanker/DbModels/ProvisionalUserKeys.hpp>
#include <Tanker/DbModels/ResourceKeys.hpp>
#include <Tanker/DbModels/TrustchainInfo.hpp>
#include <Tanker/DbModels/UserKeys.hpp>
#include <Tanker/DbModels/Version.hpp>
#include <Tanker/DbModels/Versions.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <optional>
#include <sqlite3.h>
#include <sqlpp11/functions.h>
#include <sqlpp11/insert.h>
#include <sqlpp11/select.h>
#include <sqlpp11/sqlite3/insert_or.h>
#include <sqlpp11/verbatim.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <memory>
#include <string>
#include <vector>

TLOG_CATEGORY(Database);

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace DataStore
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

template <typename T>
InternalGroup rowToInternalGroup(T const& row)
{
  assert(!row.private_signature_key.is_null() &&
         !row.private_encryption_key.is_null());

  return InternalGroup{
      DataStore::extractBlob<GroupId>(row.group_id),
      {DataStore::extractBlob<Crypto::PublicSignatureKey>(
           row.public_signature_key),
       DataStore::extractBlob<Crypto::PrivateSignatureKey>(
           row.private_signature_key)},
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(
           row.public_encryption_key),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
           row.private_encryption_key)},
      DataStore::extractBlob<Crypto::Hash>(row.last_group_block_hash)};
}

template <typename T>
ExternalGroup rowToExternalGroup(T const& row)
{
  return ExternalGroup{
      DataStore::extractBlob<GroupId>(row.group_id),
      DataStore::extractBlob<Crypto::PublicSignatureKey>(
          row.public_signature_key),
      row.encrypted_private_signature_key.is_null() ?
          std::optional<Crypto::SealedPrivateSignatureKey>{} :
          DataStore::extractBlob<Crypto::SealedPrivateSignatureKey>(
              row.encrypted_private_signature_key),
      DataStore::extractBlob<Crypto::PublicEncryptionKey>(
          row.public_encryption_key),
      DataStore::extractBlob<Crypto::Hash>(row.last_group_block_hash)};
}

template <typename T>
Group rowToGroup(T const& row)
{
  if (row.encrypted_private_signature_key.is_null())
    return rowToInternalGroup(row);
  else
    return rowToExternalGroup(row);
}
}

using UserKeysTable = DbModels::user_keys::user_keys;
using TrustchainInfoTable = DbModels::trustchain_info::trustchain_info;
using ContactUserKeysTable = DbModels::contact_user_keys::contact_user_keys;
using ResourceKeysTable = DbModels::resource_keys::resource_keys;
using ProvisionalUserKeysTable =
    DbModels::provisional_user_keys::provisional_user_keys;
using DeviceKeysTable = DbModels::device_key_store::device_key_store;
using ContactDevicesTable = DbModels::contact_devices::contact_devices;
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
      createTable<ContactDevicesTable>(*_db);
      createTable<ContactUserKeysTable>(*_db);
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
      flushAllCaches();
      [[fallthrough]];
    case 6:
      _db->execute("DROP TABLE IF EXISTS trustchain");
      _db->execute("DROP TABLE IF EXISTS contact_devices");
      createTable<ContactDevicesTable>(*_db);
      _db->execute("DROP TABLE IF EXISTS groups");
      createTable<GroupsTable>(*_db);
      break;
    default:
      throw Errors::formatEx(Errc::InvalidDatabaseVersion,
                             "invalid database version: {}",
                             currentVersion);
    }

    setDatabaseVersion(DataStore::latestVersion());
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
  createOrMigrateTable<ContactDevicesTable>(
      currentTableVersion<ContactDevicesTable>());
  createOrMigrateTable<ContactUserKeysTable>(
      currentTableVersion<ContactUserKeysTable>());
  createTable<VersionTable>(*_db);

  setDatabaseVersion(3);
  dropTable<OldVersionsTable>();
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

void Database::flushAllCaches()
{
  FUNC_TIMER(DB);
  auto const flushTable = [this](auto const& tab) {
    (*_db)(remove_from(tab).unconditionally());
  };

  // flush all tables but DeviceKeysTable
  // Order matter for foreign key constraints
  flushTable(ContactDevicesTable{});
  flushTable(UserKeysTable{});
  flushTable(ContactUserKeysTable{});
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

  {
    DeviceKeysTable tab{};
    (*_db)(
        update(tab).set(tab.device_id = DeviceId{}.base()).unconditionally());
  }
}

template <typename Table>
void Database::dropTable()
{
  _db->execute(fmt::format(TFMT("DROP TABLE {:s}"), tableName<Table>()));
}

tc::cotask<void> Database::nuke()
{
  FUNC_TIMER(DB);
  flushAllCaches();
  {
    DeviceKeysTable tab{};
    (*_db)(remove_from(tab).unconditionally());
  }
  TC_RETURN();
}

tc::cotask<void> Database::startTransaction()
{
  FUNC_TIMER(DB);
  _transactions.push_back(start_transaction(*_db));
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

tc::cotask<void> Database::putUserPrivateKey(
    Crypto::PublicEncryptionKey const& publicKey,
    Crypto::PrivateEncryptionKey const& privateKey)
{
  FUNC_TIMER(DB);
  UserKeysTable tab{};
  (*_db)(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.public_encryption_key = publicKey.base(),
      tab.private_encryption_key = privateKey.base()));
  TC_RETURN();
}

tc::cotask<Crypto::EncryptionKeyPair> Database::getUserKeyPair(
    Crypto::PublicEncryptionKey const& publicKey)
{
  FUNC_TIMER(DB);
  UserKeysTable tab{};

  auto rows = (*_db)(select(tab.private_encryption_key)
                         .from(tab)
                         .where(tab.public_encryption_key == publicKey.base()));
  if (rows.empty())
  {
    throw Errors::formatEx(Errc::RecordNotFound,
                           TFMT("could not find user key for {:s}"),
                           publicKey);
  }
  auto const& row = *rows.begin();

  TC_RETURN((Crypto::EncryptionKeyPair{
      publicKey,
      DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
          row.private_encryption_key)}));
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
Database::getUserOptLastKeyPair()
{
  FUNC_TIMER(DB);
  UserKeysTable tab{};

  auto rows =
      (*_db)(select(tab.public_encryption_key, tab.private_encryption_key)
                 .from(tab)
                 .order_by(tab.id.desc())
                 .limit(1u)
                 .unconditionally());
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = *rows.begin();

  TC_RETURN((std::optional<Crypto::EncryptionKeyPair>{
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(
           row.public_encryption_key),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
           row.private_encryption_key)}}));
}

tc::cotask<std::optional<Crypto::PublicSignatureKey>>
Database::findTrustchainPublicSignatureKey()
{
  FUNC_TIMER(DB);
  TrustchainInfoTable tab{};
  auto rows = (*_db)(
      select(tab.trustchain_public_signature_key).from(tab).unconditionally());
  if (rows.empty())
  {
    throw Errors::AssertionError(
        "trustchain_info table must have a single row");
  }
  if (rows.front().trustchain_public_signature_key.is_null())
    TC_RETURN(std::nullopt);
  TC_RETURN(DataStore::extractBlob<Crypto::PublicSignatureKey>(
      rows.front().trustchain_public_signature_key));
}

tc::cotask<void> Database::setTrustchainPublicSignatureKey(
    Crypto::PublicSignatureKey const& key)
{
  FUNC_TIMER(DB);
  TrustchainInfoTable tab{};
  (*_db)(update(tab)
             .set(tab.trustchain_public_signature_key = key.base())
             .unconditionally());
  TC_RETURN();
}

tc::cotask<void> Database::putContact(
    UserId const& userId,
    std::optional<Crypto::PublicEncryptionKey> const& publicKey)
{
  FUNC_TIMER(DB);
  ContactUserKeysTable tab{};

  if (publicKey)
  {
    (*_db)(sqlpp::sqlite3::insert_or_replace_into(tab).set(
        tab.user_id = userId.base(),
        tab.public_encryption_key = publicKey->base()));
  }
  else
  {
    // We do not want to delete a user key, so use insert_into, not
    // insert_or_*
    (*_db)(insert_into(tab).set(tab.user_id = userId.base(),
                                tab.public_encryption_key = sqlpp::null));
  }
  TC_RETURN();
}

tc::cotask<std::optional<Crypto::PublicEncryptionKey>>
Database::findContactUserKey(UserId const& userId)
{
  FUNC_TIMER(DB);
  ContactUserKeysTable tab{};
  auto rows = (*_db)(select(tab.public_encryption_key)
                         .from(tab)
                         .where(tab.user_id == userId.base()));

  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();
  if (row.public_encryption_key.is_null())
    TC_RETURN(std::nullopt);

  TC_RETURN(DataStore::extractBlob<Crypto::PublicEncryptionKey>(
      row.public_encryption_key));
}

tc::cotask<std::optional<UserId>>
Database::findContactUserIdByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& userPublicKey)
{
  FUNC_TIMER(DB);
  ContactUserKeysTable tab{};
  auto rows =
      (*_db)(select(tab.user_id)
                 .from(tab)
                 .where(tab.public_encryption_key == userPublicKey.base()));

  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(DataStore::extractBlob<UserId>(row.user_id));
}

tc::cotask<void> Database::setContactPublicEncryptionKey(
    UserId const& userId, Crypto::PublicEncryptionKey const& userPublicKey)
{
  FUNC_TIMER(DB);
  ContactUserKeysTable tab{};
  (*_db)(update(tab)
             .set(tab.public_encryption_key = userPublicKey.base())
             .where(tab.user_id == userId.base()));
  TC_RETURN();
}

tc::cotask<void> Database::putResourceKey(ResourceId const& resourceId,
                                          Crypto::SymmetricKey const& key)
{
  FUNC_TIMER(DB);
  ResourceKeysTable tab{};

  (*_db)(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.mac = resourceId.base(), tab.resource_key = key.base()));
  TC_RETURN();
}

tc::cotask<std::optional<Crypto::SymmetricKey>> Database::findResourceKey(
    ResourceId const& resourceId)
{
  FUNC_TIMER(DB);
  ResourceKeysTable tab{};
  auto rows = (*_db)(
      select(tab.resource_key).from(tab).where(tab.mac == resourceId.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = rows.front();

  TC_RETURN(DataStore::extractBlob<Crypto::SymmetricKey>(row.resource_key));
}

tc::cotask<void> Database::putProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey,
    Tanker::ProvisionalUserKeys const& provisionalUserKeys)
{
  FUNC_TIMER(DB);
  ProvisionalUserKeysTable tab{};

  (*_db)(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.app_pub_sig_key = appPublicSigKey.base(),
      tab.tanker_pub_sig_key = tankerPublicSigKey.base(),
      tab.app_enc_priv = provisionalUserKeys.appKeys.privateKey.base(),
      tab.app_enc_pub = provisionalUserKeys.appKeys.publicKey.base(),
      tab.tanker_enc_priv = provisionalUserKeys.tankerKeys.privateKey.base(),
      tab.tanker_enc_pub = provisionalUserKeys.tankerKeys.publicKey.base()));
  TC_RETURN();
}

tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
Database::findProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey)
{
  FUNC_TIMER(DB);
  ProvisionalUserKeysTable tab{};
  auto rows =
      (*_db)(select(tab.app_enc_priv,
                    tab.app_enc_pub,
                    tab.tanker_enc_priv,
                    tab.tanker_enc_pub)
                 .from(tab)
                 .where(tab.app_pub_sig_key == appPublicSigKey.base() and
                        tab.tanker_pub_sig_key == tankerPublicSigKey.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = rows.front();
  Tanker::ProvisionalUserKeys ret{
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.app_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(row.app_enc_priv)},
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.tanker_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
           row.tanker_enc_priv)}};
  TC_RETURN(ret);
}

tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
Database::findProvisionalUserKeysByAppPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& appPublicEncryptionKey)
{
  FUNC_TIMER(DB);
  ProvisionalUserKeysTable tab{};
  auto rows =
      (*_db)(select(tab.app_enc_priv,
                    tab.app_enc_pub,
                    tab.tanker_enc_priv,
                    tab.tanker_enc_pub)
                 .from(tab)
                 .where(tab.app_enc_pub == appPublicEncryptionKey.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = rows.front();
  Tanker::ProvisionalUserKeys ret{
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.app_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(row.app_enc_priv)},
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(row.tanker_enc_pub),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
           row.tanker_enc_priv)}};
  TC_RETURN(ret);
}

tc::cotask<std::optional<DeviceKeys>> Database::getDeviceKeys()
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  auto rows = (*_db)(select(tab.private_signature_key,
                            tab.public_signature_key,
                            tab.private_encryption_key,
                            tab.public_encryption_key,
                            tab.device_id)
                         .from(tab)
                         .unconditionally());
  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = rows.front();
  TC_RETURN((DeviceKeys{{DataStore::extractBlob<Crypto::PublicSignatureKey>(
                             row.public_signature_key),
                         DataStore::extractBlob<Crypto::PrivateSignatureKey>(
                             row.private_signature_key)},
                        {DataStore::extractBlob<Crypto::PublicEncryptionKey>(
                             row.public_encryption_key),
                         DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
                             row.private_encryption_key)}}));
}

tc::cotask<void> Database::setDeviceKeys(DeviceKeys const& deviceKeys)
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  (*_db)(insert_into(tab).set(
      tab.private_signature_key = deviceKeys.signatureKeyPair.privateKey.base(),
      tab.public_signature_key = deviceKeys.signatureKeyPair.publicKey.base(),
      tab.private_encryption_key =
          deviceKeys.encryptionKeyPair.privateKey.base(),
      tab.public_encryption_key =
          deviceKeys.encryptionKeyPair.publicKey.base()));
  TC_RETURN();
}

tc::cotask<void> Database::setDeviceId(Trustchain::DeviceId const& deviceId)
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  (*_db)(update(tab).set(tab.device_id = deviceId.base()).unconditionally());
  TC_RETURN();
}

tc::cotask<std::optional<Trustchain::DeviceId>> Database::getDeviceId()
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  auto rows = (*_db)(select(tab.device_id).from(tab).unconditionally());
  if (rows.empty())
    TC_RETURN(std::nullopt);
  auto const& row = rows.front();
  if (row.device_id.len == 0)
    TC_RETURN(std::nullopt);
  TC_RETURN((DataStore::extractBlob<Trustchain::DeviceId>(row.device_id)));
}

tc::cotask<void> Database::putDevice(Users::Device const& device)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  (*_db)(sqlpp::sqlite3::insert_or_replace_into(tab).set(
      tab.id = device.id().base(),
      tab.user_id = device.userId().base(),
      tab.public_signature_key = device.publicSignatureKey().base(),
      tab.public_encryption_key = device.publicEncryptionKey().base(),
      tab.is_ghost_device = device.isGhostDevice(),
      tab.is_revoked = device.isRevoked()));
  TC_RETURN();
}

tc::cotask<std::optional<Users::Device>> Database::findDevice(
    Trustchain::DeviceId const& id)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  auto rows = (*_db)(select(all_of(tab)).from(tab).where(tab.id == id.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(rowToDevice(row));
}

tc::cotask<std::vector<Users::Device>> Database::getDevicesOf(UserId const& id)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  auto rows =
      (*_db)(select(all_of(tab)).from(tab).where(tab.user_id == id.base()));

  std::vector<Users::Device> ret;
  for (auto const& row : rows)
    ret.push_back(rowToDevice(row));
  TC_RETURN(ret);
}

tc::cotask<std::optional<UserId>> Database::findDeviceUserId(
    Trustchain::DeviceId const& id)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  auto rows = (*_db)(select(tab.user_id).from(tab).where(tab.id == id.base()));
  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(DataStore::extractBlob<UserId>(row.user_id));
}

tc::cotask<void> Database::setDeviceRevoked(Trustchain::DeviceId const& id)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  (*_db)(update(tab).set(tab.is_revoked = true).where(tab.id == id.base()));

  TC_RETURN();
}

tc::cotask<void> Database::putInternalGroup(InternalGroup const& group)
{
  FUNC_TIMER(DB);
  GroupsTable groups;

  (*_db)(sqlpp::sqlite3::insert_or_replace_into(groups).set(
      groups.group_id = group.id.base(),
      groups.public_signature_key = group.signatureKeyPair.publicKey.base(),
      groups.private_signature_key = group.signatureKeyPair.privateKey.base(),
      groups.encrypted_private_signature_key = sqlpp::null,
      groups.public_encryption_key = group.encryptionKeyPair.publicKey.base(),
      groups.private_encryption_key = group.encryptionKeyPair.privateKey.base(),
      groups.last_group_block_hash = group.lastBlockHash.base()));
  TC_RETURN();
}

tc::cotask<void> Database::putExternalGroup(ExternalGroup const& group)
{
  FUNC_TIMER(DB);
  if (!group.encryptedPrivateSignatureKey)
  {
    throw Errors::AssertionError(
        "external groups must be inserted with their sealed private signature "
        "key");
  }

  GroupsTable groups;

  (*_db)(sqlpp::sqlite3::insert_or_replace_into(groups).set(
      groups.group_id = group.id.base(),
      groups.public_signature_key = group.publicSignatureKey.base(),
      groups.private_signature_key = sqlpp::null,
      groups.encrypted_private_signature_key =
          group.encryptedPrivateSignatureKey->base(),
      groups.public_encryption_key = group.publicEncryptionKey.base(),
      groups.private_encryption_key = sqlpp::null,
      groups.last_group_block_hash = group.lastBlockHash.base()));

  TC_RETURN();
}

tc::cotask<std::optional<Group>> Database::findGroupByGroupId(
    GroupId const& groupId)
{
  FUNC_TIMER(DB);
  GroupsTable groups{};

  auto rows = (*_db)(select(all_of(groups))
                         .from(groups)
                         .where(groups.group_id == groupId.base()));

  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(rowToGroup(row));
}

tc::cotask<std::optional<Group>> Database::findGroupByGroupPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  FUNC_TIMER(DB);
  GroupsTable groups{};

  auto rows = (*_db)(
      select(all_of(groups))
          .from(groups)
          .where(groups.public_encryption_key == publicEncryptionKey.base()));

  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(rowToGroup(row));
}
}
}
