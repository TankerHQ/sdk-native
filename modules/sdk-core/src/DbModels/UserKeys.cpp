#include <Tanker/DbModels/UserKeys.hpp>

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/Log/Log.hpp>

#include <Tanker/Errors/AssertionError.hpp>

#include <mgs/base64.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(user_keys);

namespace Tanker
{
namespace DbModels
{
namespace user_keys
{
namespace
{
void migrate1To2(DataStore::Connection& db)
{
  using DataStore::extractBlob;

  user_keys tab{};
  auto rows = db(select(all_of(tab)).from(tab).unconditionally());
  for (auto const& row : rows)
  {
    auto const pubK = mgs::base64::decode<Crypto::PublicEncryptionKey>(
        extractBlob(row.public_encryption_key));
    auto const privK = mgs::base64::decode<Crypto::PrivateEncryptionKey>(
        extractBlob(row.private_encryption_key));

    db(update(tab)
           .set(tab.public_encryption_key = pubK.base(),
                tab.private_encryption_key = privK.base())
           .where(tab.id == row.id));
  }
}
}

void createTable(DataStore::Connection& db, user_keys const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS user_keys (
      id INTEGER PRIMARY KEY,
      public_encryption_key BLOB NOT NULL UNIQUE,
      private_encryption_key BLOB NOT NULL
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int currentVersion,
                  user_keys const&)
{
  assert(currentVersion < DataStore::latestVersion());

  TINFO("Migrating from version {} to {}",
        currentVersion,
        DataStore::latestVersion());
  switch (currentVersion)
  {
  case 0:
  case 1:
    migrate1To2(db);
    // fallthrough
  case 2:
    break;
  default:
    throw Tanker::Errors::AssertionError("Unreachable code");
    std::terminate();
  }
}
}
}
}
