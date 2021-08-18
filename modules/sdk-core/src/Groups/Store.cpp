#include <Tanker/Groups/Store.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/GroupKeys.hpp>
#include <Tanker/DbModels/Groups.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <sqlpp11/sqlite3/insert_or.h>

#include <optional>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(GroupStore);

using Tanker::Trustchain::GroupId;

using GroupsTable = Tanker::DbModels::groups::groups;

namespace Tanker::Groups
{
namespace
{
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
      DataStore::extractBlob<Crypto::Hash>(row.last_group_block_hash),
      DataStore::extractBlob<Crypto::Hash>(row.last_key_rotation_block_hash)};
}

template <typename T>
ExternalGroup rowToExternalGroup(T const& row)
{
  return ExternalGroup{
      DataStore::extractBlob<GroupId>(row.group_id),
      DataStore::extractBlob<Crypto::PublicSignatureKey>(
          row.public_signature_key),
      DataStore::extractBlob<Crypto::SealedPrivateSignatureKey>(
          row.encrypted_private_signature_key),
      DataStore::extractBlob<Crypto::PublicEncryptionKey>(
          row.public_encryption_key),
      DataStore::extractBlob<Crypto::Hash>(row.last_group_block_hash),
      DataStore::extractBlob<Crypto::Hash>(row.last_key_rotation_block_hash)};
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

Store::Store(DataStore::Database* dbConn) : _db(dbConn)
{
}

tc::cotask<void> Store::put(Group const& group)
{
  TC_AWAIT(boost::variant2::visit(
      [this](auto const& g) -> tc::cotask<void> { TC_AWAIT(this->put(g)); },
      group));
}

tc::cotask<void> Store::put(InternalGroup const& group)
{
  TINFO("Adding internal group {}", group.id);
  FUNC_TIMER(DB);
  GroupsTable groups;

  (*_db->connection())(sqlpp::sqlite3::insert_or_replace_into(groups).set(
      groups.group_id = group.id.base(),
      groups.public_signature_key = group.signatureKeyPair.publicKey.base(),
      groups.private_signature_key = group.signatureKeyPair.privateKey.base(),
      groups.encrypted_private_signature_key = sqlpp::null,
      groups.public_encryption_key = group.encryptionKeyPair.publicKey.base(),
      groups.private_encryption_key = group.encryptionKeyPair.privateKey.base(),
      groups.last_group_block_hash = group.lastBlockHash.base(),
      groups.last_key_rotation_block_hash =
          group.lastKeyRotationBlockHash.base()));
  TC_RETURN();
}

tc::cotask<void> Store::put(ExternalGroup const& group)
{
  TINFO("Adding external group {}", group.id);
  FUNC_TIMER(DB);

  GroupsTable groups;

  (*_db->connection())(sqlpp::sqlite3::insert_or_replace_into(groups).set(
      groups.group_id = group.id.base(),
      groups.public_signature_key = group.publicSignatureKey.base(),
      groups.private_signature_key = sqlpp::null,
      groups.encrypted_private_signature_key =
          group.encryptedPrivateSignatureKey.base(),
      groups.public_encryption_key = group.publicEncryptionKey.base(),
      groups.private_encryption_key = sqlpp::null,
      groups.last_group_block_hash = group.lastBlockHash.base(),
      groups.last_key_rotation_block_hash =
          group.lastKeyRotationBlockHash.base()));

  TC_RETURN();
}

tc::cotask<std::optional<Group>> Store::findById(GroupId const& groupId) const
{
  FUNC_TIMER(DB);
  GroupsTable groups;

  auto rows =
      (*_db->connection())(select(all_of(groups))
                               .from(groups)
                               .where(groups.group_id == groupId.base()));

  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();

  TC_RETURN(rowToGroup(row));
}

tc::cotask<std::optional<InternalGroup>>
Store::findInternalByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  auto optGroup = TC_AWAIT(findByPublicEncryptionKey(publicEncryptionKey));
  if (!optGroup ||
      !boost::variant2::holds_alternative<InternalGroup>(*optGroup))
    TC_RETURN(std::nullopt);
  TC_RETURN(boost::variant2::get<InternalGroup>(*optGroup));
}

tc::cotask<std::optional<Group>> Store::findByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  FUNC_TIMER(DB);
  GroupsTable groups;

  auto rows = (*_db->connection())(
      select(all_of(groups))
          .from(groups)
          .where(groups.public_encryption_key == publicEncryptionKey.base()));

  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();
  TC_RETURN(rowToGroup(row));
}
}
