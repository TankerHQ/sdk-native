#include <Tanker/DbModels/DeviceKeyStore.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <cassert>
#include <exception>

TLOG_CATEGORY(device_key_store);

namespace Tanker
{
namespace DbModels
{
namespace device_key_store
{
namespace
{
void migrate1To2(DataStore::Connection& db)
{
  using DataStore::extractBlob;

  device_key_store tab;
  auto rows = db(select(all_of(tab)).from(tab).unconditionally());
  for (auto const& row : rows)
  {
    auto const privSigK = base64::decode<Crypto::PrivateSignatureKey>(
        extractBlob(row.private_signature_key));
    auto const pubSigK = base64::decode<Crypto::PublicSignatureKey>(
        extractBlob(row.public_signature_key));
    auto const privEncK = base64::decode<Crypto::PrivateEncryptionKey>(
        extractBlob(row.private_encryption_key));
    auto const pubEncK = base64::decode<Crypto::PublicEncryptionKey>(
        extractBlob(row.public_encryption_key));
    auto const deviceId = base64::decode<DeviceId>(extractBlob(row.device_id));

    db(update(tab)
           .set(tab.private_signature_key = privSigK.base(),
                tab.public_signature_key = pubSigK.base(),
                tab.private_encryption_key = privEncK.base(),
                tab.public_encryption_key = pubEncK.base(),
                tab.device_id = deviceId.base())
           .where(tab.id == row.id));
  }
}
}

void createTable(DataStore::Connection& db, device_key_store const&)
{
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS device_key_store (
      id INTEGER PRIMARY KEY,
      private_signature_key BLOB NOT NULL,
      public_signature_key BLOB NOT NULL,
      private_encryption_key BLOB NOT NULL,
      public_encryption_key BLOB NOT NULL,
      device_id BLOB
    );
  )");
}

void migrateTable(DataStore::Connection& db,
                  int dbVersion,
                  device_key_store const&)
{
  assert(dbVersion < currentTableVersion());

  TINFO("Migrating from version {} to {}", dbVersion, currentTableVersion());
  switch (dbVersion)
  {
  case 0:
  case 1:
    migrate1To2(db);
    break;
  default:
    assert(false && "Unreachable code");
    std::terminate();
  }
}
}
}
}
