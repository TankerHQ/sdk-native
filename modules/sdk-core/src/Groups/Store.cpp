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

using GroupKeysTable = Tanker::DbModels::group_keys::group_keys;

namespace Tanker::Groups
{


Store::Store(DataStore::Database* dbConn) : _db(dbConn)
{
}

tc::cotask<void> Store::putKeys(
    Trustchain::GroupId const& id,
    std::vector<Crypto::EncryptionKeyPair> const& keys)
{
  TINFO("Adding internal group keys for group {}", id);
  FUNC_TIMER(DB);
  GroupKeysTable groupKeys;

  TC_AWAIT(_db->inTransaction([&]() -> tc::cotask<void> {
    for (auto const& key : keys)
      (*_db->connection())(
          sqlpp::sqlite3::insert_or_replace_into(groupKeys).set(
              groupKeys.public_encryption_key = key.publicKey.base(),
              groupKeys.private_encryption_key = key.privateKey.base(),
              groupKeys.group_id = id.base()));
  }));

  TC_RETURN();
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
Store::findKeyByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey) const
{
  FUNC_TIMER(DB);
  GroupKeysTable groupKeys;

  auto rows = (*_db->connection())(select(all_of(groupKeys))
                                       .from(groupKeys)
                                       .where(groupKeys.public_encryption_key ==
                                              publicEncryptionKey.base()));

  if (rows.empty())
    TC_RETURN(std::nullopt);

  auto const& row = *rows.begin();
  auto key = Crypto::EncryptionKeyPair{
      DataStore::extractBlob<Crypto::PublicEncryptionKey>(
          row.public_encryption_key),
      DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
          row.private_encryption_key),
  };
  TC_RETURN(key);
}
}
