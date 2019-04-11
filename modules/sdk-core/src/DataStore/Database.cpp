#include <Tanker/DataStore/Database.hpp>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/KeyPublishToUser.hpp>
#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ContactDevices.hpp>
#include <Tanker/DbModels/ContactUserKeys.hpp>
#include <Tanker/DbModels/DeviceKeyStore.hpp>
#include <Tanker/DbModels/Groups.hpp>
#include <Tanker/DbModels/ResourceIdToKeyPublish.hpp>
#include <Tanker/DbModels/ResourceKeys.hpp>
#include <Tanker/DbModels/Trustchain.hpp>
#include <Tanker/DbModels/TrustchainIndexes.hpp>
#include <Tanker/DbModels/UserKeys.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <fmt/format.h>
#include <mpark/variant.hpp>
#include <optional.hpp>
#include <sqlite3.h>
#include <sqlpp11/functions.h>
#include <sqlpp11/insert.h>
#include <sqlpp11/select.h>
#include <sqlpp11/sqlite3/insert_or.h>
#include <sqlpp11/verbatim.h>

#include <array>
#include <cassert>
#include <memory>
#include <string>
#include <vector>

TLOG_CATEGORY(Database);

namespace Tanker
{
namespace DataStore
{
namespace
{
template <typename Row>
Device rowToDevice(Row const& row)
{
  nonstd::optional<uint64_t> revokedAtBlockIndex;
  if (!row.revoked_at_block_index.is_null())
    revokedAtBlockIndex = static_cast<uint64_t>(row.revoked_at_block_index);

  return {DataStore::extractBlob<DeviceId>(row.id),
          static_cast<uint64_t>(row.created_at_block_index),
          std::move(revokedAtBlockIndex),
          DataStore::extractBlob<Crypto::PublicSignatureKey>(
              row.public_signature_key),
          DataStore::extractBlob<Crypto::PublicEncryptionKey>(
              row.public_encryption_key),
          row.is_ghost_device};
}

template <typename Row>
Entry rowToEntry(Row const& row)
{
  using DataStore::extractBlob;

  return Entry{
      static_cast<uint64_t>(row.idx),
      static_cast<Nature>(static_cast<unsigned>(row.nature)),
      extractBlob<Crypto::Hash>(row.author),
      deserializeAction(static_cast<Nature>(static_cast<unsigned>(row.nature)),
                        extractBlob(row.action)),
      extractBlob<Crypto::Hash>(row.hash),
  };
}

template <typename T>
Group rowToFullGroup(T const& row)
{
  assert(!row.private_signature_key.is_null() &&
         !row.private_encryption_key.is_null());

  return Group{DataStore::extractBlob<GroupId>(row.group_id),
               {DataStore::extractBlob<Crypto::PublicSignatureKey>(
                    row.public_signature_key),
                DataStore::extractBlob<Crypto::PrivateSignatureKey>(
                    row.private_signature_key)},
               {DataStore::extractBlob<Crypto::PublicEncryptionKey>(
                    row.public_encryption_key),
                DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
                    row.private_encryption_key)},
               DataStore::extractBlob<Crypto::Hash>(row.last_group_block_hash),
               // sqlpp uses int64_t
               static_cast<uint64_t>(row.last_group_block_index)};
}

template <typename T>
ExternalGroup rowToExternalGroup(T const& row)
{
  return ExternalGroup{
      DataStore::extractBlob<GroupId>(row.group_id),
      DataStore::extractBlob<Crypto::PublicSignatureKey>(
          row.public_signature_key),
      row.encrypted_private_signature_key.is_null() ?
          nonstd::optional<Crypto::SealedPrivateSignatureKey>{} :
          DataStore::extractBlob<Crypto::SealedPrivateSignatureKey>(
              row.encrypted_private_signature_key),
      DataStore::extractBlob<Crypto::PublicEncryptionKey>(
          row.public_encryption_key),
      DataStore::extractBlob<Crypto::Hash>(row.last_group_block_hash),
      // sqlpp uses int64_t
      static_cast<uint64_t>(row.last_group_block_index)};
}
}

using UserKeysTable = DbModels::user_keys::user_keys;
using TrustchainTable = DbModels::trustchain::trustchain;
using TrustchainIndexesTable = DbModels::trustchain_indexes::trustchain_indexes;
using TrustchainResourceIdToKeyPublishTable =
    DbModels::resource_id_to_key_publish::resource_id_to_key_publish;
using ContactUserKeysTable = DbModels::contact_user_keys::contact_user_keys;
using ResourceKeysTable = DbModels::resource_keys::resource_keys;
using DeviceKeysTable = DbModels::device_key_store::device_key_store;
using ContactDevicesTable = DbModels::contact_devices::contact_devices;
using GroupsTable = DbModels::groups::groups;

Database::Database(std::string const& dbPath,
                   nonstd::optional<Crypto::SymmetricKey> const& userSecret,
                   bool exclusive)
  : _db(createConnection(dbPath, userSecret, exclusive))
{
  DataStore::createOrMigrateTable<UserKeysTable>(*_db);
  DataStore::createOrMigrateTable<TrustchainTable>(*_db);
  DataStore::createOrMigrateTable<TrustchainIndexesTable>(*_db);
  DataStore::createOrMigrateTable<TrustchainResourceIdToKeyPublishTable>(*_db);
  DataStore::createOrMigrateTable<ContactUserKeysTable>(*_db);
  DataStore::createOrMigrateTable<ResourceKeysTable>(*_db);
  DataStore::createOrMigrateTable<DeviceKeysTable>(*_db);
  DataStore::createOrMigrateTable<ContactDevicesTable>(*_db);
  DataStore::createOrMigrateTable<GroupsTable>(*_db);

  if (isMigrationNeeded())
  {
    TINFO("Migration is needed, flushing caches");
    flushAllCaches();
  }
}

bool Database::isMigrationNeeded()
{
  FUNC_TIMER(DB);
  auto const deviceCount = [&] {
    ContactDevicesTable tab{};
    auto rows = (*_db)(select(count(tab.id)).from(tab).unconditionally());
    auto const& row = *rows.begin();
    return int(row.count);
  }();
  auto const blockCount = [&] {
    TrustchainTable tab{};
    auto rows = (*_db)(select(count(tab.hash)).from(tab).unconditionally());
    auto const& row = *rows.begin();
    return int(row.count);
  }();

  // if there are blocks in the trustchain table but there are no devices (even
  // ours), it means that we must migrate
  return deviceCount == 0 && blockCount > 0;
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
  flushTable(TrustchainIndexesTable{});
  flushTable(TrustchainResourceIdToKeyPublishTable{});
  flushTable(TrustchainTable{});
  flushTable(ContactUserKeysTable{});
  flushTable(ResourceKeysTable{});
  flushTable(GroupsTable{});
}

tc::cotask<void> Database::nuke()
{
  FUNC_TIMER(DB);
  flushAllCaches();
  DeviceKeysTable tab{};
  (*_db)(remove_from(tab).unconditionally());
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
    throw Error::formatEx<RecordNotFound>(
        fmt("couldn't find user key for {:s}"), publicKey);
  auto const& row = *rows.begin();

  TC_RETURN((Crypto::EncryptionKeyPair{
      publicKey,
      DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
          row.private_encryption_key)}));
}

tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
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
    TC_RETURN(nonstd::nullopt);
  auto const& row = *rows.begin();

  TC_RETURN((nonstd::optional<Crypto::EncryptionKeyPair>{
      {DataStore::extractBlob<Crypto::PublicEncryptionKey>(
           row.public_encryption_key),
       DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
           row.private_encryption_key)}}));
}

tc::cotask<uint64_t> Database::getTrustchainLastIndex()
{
  FUNC_TIMER(DB);
  TrustchainTable tab{};
  TC_RETURN(
      (*_db)(select(max(tab.idx)).from(tab).unconditionally()).front().max);
}

tc::cotask<void> Database::addTrustchainEntry(Entry const& entry)
{
  FUNC_TIMER(DB);
  TrustchainTable tab{};
  (*_db)(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.idx = entry.index,
      tab.nature = static_cast<unsigned>(entry.action.nature()),
      tab.author = entry.author.base(),
      tab.action = Serialization::serialize(entry.action),
      tab.hash = entry.hash.base()));

  auto const insertedCount = sqlite3_changes(_db->native_handle());

  // if row was already there, we are done
  if (insertedCount == 0)
    TC_RETURN();

  if (auto const keyPublish =
          mpark::get_if<KeyPublishToUser>(&entry.action.variant()))
    TC_AWAIT(indexKeyPublish(entry.hash, keyPublish->mac));
  if (auto const keyPublish =
          mpark::get_if<KeyPublishToUserGroup>(&entry.action.variant()))
    TC_AWAIT(indexKeyPublish(entry.hash, keyPublish->resourceId));

  for (auto const& index : entry.action.makeIndexes())
  {
    TrustchainIndexesTable indexTable;

    (*_db)(sqlpp::sqlite3::insert_or_ignore_into(indexTable)
               .set(indexTable.hash = entry.hash.base(),
                    indexTable.type = static_cast<unsigned>(index.type),
                    indexTable.value = index.value));
  }
}

tc::cotask<nonstd::optional<Entry>> Database::findTrustchainEntry(
    Crypto::Hash const& hash)
{
  FUNC_TIMER(DB);
  TrustchainTable tab{};

  auto rows =
      (*_db)(select(all_of(tab)).from(tab).where(tab.hash == hash.base()));

  if (rows.empty())
    TC_RETURN(nonstd::nullopt);
  TC_RETURN(rowToEntry(*rows.begin()));
}

tc::cotask<void> Database::indexKeyPublish(Crypto::Hash const& hash,
                                           Crypto::Mac const& resourceId)
{
  TrustchainResourceIdToKeyPublishTable tab{};
  (*_db)(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.resource_id = resourceId.base(), tab.hash = hash.base()));
  TC_RETURN();
}

tc::cotask<nonstd::optional<Entry>> Database::findTrustchainKeyPublish(
    Crypto::Mac const& resourceId)
{
  FUNC_TIMER(DB);
  TrustchainResourceIdToKeyPublishTable tab_index;
  TrustchainTable tab_trustchain{};
  auto rows = (*_db)(select(tab_trustchain.idx,
                            tab_trustchain.author,
                            tab_trustchain.nature,
                            tab_trustchain.action,
                            tab_trustchain.hash)
                         .from(tab_index.join(tab_trustchain)
                                   .on(tab_index.hash == tab_trustchain.hash))
                         .where(tab_index.resource_id == resourceId.base()));

  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(rowToEntry(rows.front()));
}

tc::cotask<std::vector<Entry>> Database::getTrustchainDevicesOf(
    UserId const& userId)
{
  FUNC_TIMER(DB);
  TrustchainIndexesTable tab_index;
  TrustchainTable tab_trustchain;
  auto rows = (*_db)(
      select(tab_trustchain.idx,
             tab_trustchain.author,
             tab_trustchain.nature,
             tab_trustchain.action,
             tab_trustchain.hash)
          .from(tab_index.join(tab_trustchain)
                    .on(tab_index.hash == tab_trustchain.hash))
          .where(tab_index.type == static_cast<unsigned>(IndexType::UserId) and
                 tab_index.value == userId.base())
          .order_by(tab_trustchain.idx.asc()));

  std::vector<Entry> ret;
  if (rows.empty())
    TC_RETURN(ret);

  for (auto const& row : rows)
    ret.push_back(rowToEntry(row));
  TC_RETURN(ret);
}

tc::cotask<Entry> Database::getTrustchainDevice(DeviceId const& deviceId)
{
  FUNC_TIMER(DB);
  TrustchainTable tab_trustchain;
  auto rows = (*_db)(select(tab_trustchain.idx,
                            tab_trustchain.author,
                            tab_trustchain.nature,
                            tab_trustchain.action,
                            tab_trustchain.hash)
                         .from(tab_trustchain)
                         .where(tab_trustchain.hash == deviceId.base()));
  if (rows.empty())
    throw Error::formatEx<RecordNotFound>(
        fmt("couldn't find block with hash {:s}"), deviceId);
  auto const& row = *rows.begin();

  auto const entry = rowToEntry(row);

  if (!mpark::get_if<DeviceCreation>(&entry.action.variant()))
    throw Error::formatEx<RecordNotFound>(
        fmt("the block {:s} is not a device creation"), entry.hash);

  TC_RETURN(entry);
}

tc::cotask<void> Database::putContact(
    UserId const& userId,
    nonstd::optional<Crypto::PublicEncryptionKey> const& publicKey)
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

tc::cotask<nonstd::optional<Crypto::PublicEncryptionKey>>
Database::findContactUserKey(UserId const& userId)
{
  FUNC_TIMER(DB);
  ContactUserKeysTable tab{};
  auto rows = (*_db)(select(tab.public_encryption_key)
                         .from(tab)
                         .where(tab.user_id == userId.base()));

  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  auto const& row = *rows.begin();
  if (row.public_encryption_key.is_null())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(DataStore::extractBlob<Crypto::PublicEncryptionKey>(
      row.public_encryption_key));
}

tc::cotask<nonstd::optional<UserId>>
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
    TC_RETURN(nonstd::nullopt);

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

tc::cotask<void> Database::putResourceKey(Crypto::Mac const& mac,
                                          Crypto::SymmetricKey const& key)
{
  FUNC_TIMER(DB);
  ResourceKeysTable tab{};

  (*_db)(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.mac = mac.base(), tab.resource_key = key.base()));
  TC_RETURN();
}

tc::cotask<nonstd::optional<Crypto::SymmetricKey>> Database::findResourceKey(
    Crypto::Mac const& mac)
{
  FUNC_TIMER(DB);
  ResourceKeysTable tab{};
  auto rows =
      (*_db)(select(tab.resource_key).from(tab).where(tab.mac == mac.base()));
  if (rows.empty())
    TC_RETURN(nonstd::nullopt);
  auto const& row = rows.front();

  TC_RETURN(DataStore::extractBlob<Crypto::SymmetricKey>(row.resource_key));
}

tc::cotask<nonstd::optional<DeviceKeys>> Database::getDeviceKeys()
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
    TC_RETURN(nonstd::nullopt);

  auto const& row = rows.front();
  TC_RETURN((DeviceKeys{{DataStore::extractBlob<Crypto::PublicSignatureKey>(
                             row.public_signature_key),
                         DataStore::extractBlob<Crypto::PrivateSignatureKey>(
                             row.private_signature_key)},
                        {DataStore::extractBlob<Crypto::PublicEncryptionKey>(
                             row.public_encryption_key),
                         DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
                             row.private_encryption_key)},
                        DataStore::extractBlob<DeviceId>(row.device_id)}));
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
      tab.public_encryption_key = deviceKeys.encryptionKeyPair.publicKey.base(),
      tab.device_id = deviceKeys.deviceId.base()));
  TC_RETURN();
}

tc::cotask<void> Database::setDeviceId(DeviceId const& deviceId)
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  (*_db)(update(tab).set(tab.device_id = deviceId.base()).unconditionally());
  TC_RETURN();
}

tc::cotask<void> Database::putDevice(UserId const& userId, Device const& device)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  (*_db)(sqlpp::sqlite3::insert_or_ignore_into(tab).set(
      tab.id = device.id.base(),
      tab.user_id = userId.base(),
      tab.created_at_block_index = device.createdAtBlkIndex,
      tab.revoked_at_block_index =
          sqlpp::tvin(device.revokedAtBlkIndex.value_or(0)),
      tab.is_ghost_device = device.isGhostDevice,
      tab.public_signature_key = device.publicSignatureKey.base(),
      tab.public_encryption_key = device.publicEncryptionKey.base()));
  TC_RETURN();
}

tc::cotask<nonstd::optional<Device>> Database::findDevice(DeviceId const& id)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  auto rows = (*_db)(select(all_of(tab)).from(tab).where(tab.id == id.base()));
  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(rowToDevice(row));
}

tc::cotask<std::vector<Device>> Database::getDevicesOf(UserId const& id)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  auto rows =
      (*_db)(select(all_of(tab)).from(tab).where(tab.user_id == id.base()));

  std::vector<Device> ret;
  for (auto const& row : rows)
    ret.push_back(rowToDevice(row));
  TC_RETURN(ret);
}

tc::cotask<nonstd::optional<UserId>> Database::findDeviceUserId(
    DeviceId const& id)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  auto rows = (*_db)(select(tab.user_id).from(tab).where(tab.id == id.base()));
  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(DataStore::extractBlob<UserId>(row.user_id));
}

tc::cotask<void> Database::updateDeviceRevokedAt(DeviceId const& id,
                                                 uint64_t revokedAtBlkIndex)
{
  FUNC_TIMER(DB);
  ContactDevicesTable tab{};

  (*_db)(update(tab)
             .set(tab.revoked_at_block_index = revokedAtBlkIndex)
             .where(tab.id == id.base()));

  TC_RETURN();
}

tc::cotask<void> Database::putFullGroup(Group const& group)
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
      groups.last_group_block_hash = group.lastBlockHash.base(),
      groups.last_group_block_index = group.lastBlockIndex));
  TC_RETURN();
}

tc::cotask<void> Database::putExternalGroup(ExternalGroup const& group)
{
  FUNC_TIMER(DB);
  if (!group.encryptedPrivateSignatureKey)
    throw std::runtime_error(
        "Assertion failed: external groups must be inserted with encrypted "
        "private signature key");

  GroupsTable groups;

  (*_db)(sqlpp::sqlite3::insert_or_replace_into(groups).set(
      groups.group_id = group.id.base(),
      groups.public_signature_key = group.publicSignatureKey.base(),
      groups.private_signature_key = sqlpp::null,
      groups.encrypted_private_signature_key =
          group.encryptedPrivateSignatureKey->base(),
      groups.public_encryption_key = group.publicEncryptionKey.base(),
      groups.private_encryption_key = sqlpp::null,
      groups.last_group_block_hash = group.lastBlockHash.base(),
      groups.last_group_block_index = group.lastBlockIndex));
  TC_RETURN();
}

tc::cotask<void> Database::updateLastGroupBlock(
    GroupId const& groupId,
    Crypto::Hash const& lastBlockHash,
    uint64_t lastBlockIndex)
{
  FUNC_TIMER(DB);
  GroupsTable groups;

  (*_db)(update(groups)
             .set(groups.last_group_block_hash = lastBlockHash.base(),
                  groups.last_group_block_index = lastBlockIndex)
             .where(groups.group_id == groupId.base()));
  TC_RETURN();
}

tc::cotask<nonstd::optional<Group>> Database::findFullGroupByGroupId(
    GroupId const& groupId)
{
  FUNC_TIMER(DB);
  GroupsTable groups{};

  auto rows = (*_db)(select(all_of(groups))
                         .from(groups)
                         .where(groups.group_id == groupId.base()));

  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  auto const& row = *rows.begin();

  if (row.private_signature_key.is_null() ||
      row.private_encryption_key.is_null())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(rowToFullGroup(row));
}

tc::cotask<nonstd::optional<ExternalGroup>>
Database::findExternalGroupByGroupId(GroupId const& groupId)
{
  FUNC_TIMER(DB);
  GroupsTable groups{};

  auto rows = (*_db)(select(all_of(groups))
                         .from(groups)
                         .where(groups.group_id == groupId.base()));

  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(rowToExternalGroup(row));
}

tc::cotask<nonstd::optional<Group>>
Database::findFullGroupByGroupPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  FUNC_TIMER(DB);
  GroupsTable groups{};

  auto rows = (*_db)(
      select(all_of(groups))
          .from(groups)
          .where(groups.public_encryption_key == publicEncryptionKey.base()));

  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  auto const& row = *rows.begin();

  if (row.private_signature_key.is_null() ||
      row.private_encryption_key.is_null())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(rowToFullGroup(row));
}

tc::cotask<nonstd::optional<ExternalGroup>>
Database::findExternalGroupByGroupPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  FUNC_TIMER(DB);
  GroupsTable groups{};

  auto rows = (*_db)(
      select(all_of(groups))
          .from(groups)
          .where(groups.public_encryption_key == publicEncryptionKey.base()));

  if (rows.empty())
    TC_RETURN(nonstd::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(rowToExternalGroup(row));
}
}
}
