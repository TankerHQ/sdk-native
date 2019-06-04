#include <Tanker/DbModels/ContactUserKeys.hpp>

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/DataStore/Table.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DataStore/Version.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(contact_user_keys);

using namespace Tanker::Trustchain;

namespace Tanker
{
namespace DbModels
{
namespace contact_user_keys
{
namespace
{
void migrate1To2(DataStore::Connection& db)
{
  using DataStore::extractBlob;

  contact_user_keys tab{};
  auto rows = db(select(all_of(tab)).from(tab).unconditionally());
  for (auto const& row : rows)
  {
    auto const pubK =
        cppcodec::base64_rfc4648::decode<Crypto::PublicEncryptionKey>(
            extractBlob(row.public_encryption_key));
    auto const userId =
        cppcodec::base64_rfc4648::decode<UserId>(extractBlob(row.user_id));

    db(update(tab)
           .set(tab.public_encryption_key = pubK.base(),
                tab.user_id = userId.base())
           .where(tab.id == row.id));
  }
}

// column public_encryption_key is now nullable
void migrate2To3(DataStore::Connection& db)
{
  auto const name = DataStore::tableName<contact_user_keys>();
  auto const name_orig = name + "_orig";
  db.execute(
      fmt::format(TFMT("ALTER TABLE {:s} RENAME TO {:s}"), name, name_orig));
  createTable(db);
  db.execute(fmt::format(TFMT(R"(
      INSERT INTO {:s}(id, user_id, public_encryption_key)
      SELECT id, user_id, public_encryption_key FROM {:s})"),
                         name,
                         name_orig));
  db.execute(fmt::format("DROP TABLE {}", name_orig));
}
}

void createTable(DataStore::Connection& db, contact_user_keys const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS contact_user_keys (
      id INTEGER PRIMARY KEY,
      user_id BLOB NOT NULL UNIQUE,
      public_encryption_key BLOB
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int currentVersion,
                  contact_user_keys const&)
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
    migrate2To3(db);
    // fallthrough
  case 3:
    break;
  default:
    assert(false && "Unreachable code");
    std::terminate();
  }
}
}
}
}
