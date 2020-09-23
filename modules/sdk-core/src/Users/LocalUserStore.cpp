#include <Tanker/Users/LocalUserStore.hpp>

#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/DeviceKeyStore.hpp>
#include <Tanker/DbModels/TrustchainInfo.hpp>
#include <Tanker/DbModels/UserKeys.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <sqlpp11/sqlite3/insert_or.h>

TLOG_CATEGORY(LocalUserStore);

using UserKeysTable = Tanker::DbModels::user_keys::user_keys;
using DeviceKeysTable = Tanker::DbModels::device_key_store::device_key_store;
using TrustchainInfoTable = Tanker::DbModels::trustchain_info::trustchain_info;

namespace Tanker::Users
{
LocalUserStore::LocalUserStore(DataStore::Database* db) : _db(db)
{
}

tc::cotask<bool> LocalUserStore::isInitialized()
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  auto rows = (*_db->connection())(
      select(tab.device_initialized).from(tab).unconditionally());
  if (rows.empty())
    TC_RETURN(false);
  auto const& row = rows.front();
  TC_RETURN(row.device_initialized);
}

tc::cotask<void> LocalUserStore::setDeviceId(
    Trustchain::DeviceId const& deviceId)
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  (*_db->connection())(
      update(tab).set(tab.device_id = deviceId.base()).unconditionally());
  TC_RETURN();
}

tc::cotask<void> LocalUserStore::initializeDevice(
    Crypto::PublicSignatureKey const& trustchainPublicKey,
    std::vector<Crypto::EncryptionKeyPair> const& userKeys)
{
  TC_AWAIT(_db->inTransaction([&]() -> tc::cotask<void> {
    TC_AWAIT(setTrustchainPublicSignatureKey(trustchainPublicKey));
    TC_AWAIT(putUserKeys(userKeys));
    TC_AWAIT(setDeviceInitialized());
  }));
}

tc::cotask<void> LocalUserStore::putUserKeys(
    gsl::span<Crypto::EncryptionKeyPair const> userKeys)
{
  FUNC_TIMER(DB);
  UserKeysTable tab{};
  auto multi_insert = sqlpp::sqlite3::insert_or_ignore_into(tab).columns(
      tab.public_encryption_key, tab.private_encryption_key);
  for (auto const& [pK, sK] : userKeys)
    multi_insert.values.add(tab.public_encryption_key = pK.base(),
                            tab.private_encryption_key = sK.base());
  (*_db->connection())(multi_insert);
  TC_RETURN();
}

tc::cotask<DeviceKeys> LocalUserStore::getDeviceKeys() const
{
  auto res = TC_AWAIT(findDeviceKeys());
  if (!res)
    throw Errors::AssertionError("no device_keys in database");

  TC_RETURN(std::move(*res));
}

tc::cotask<std::optional<DeviceKeys>> LocalUserStore::findDeviceKeys() const
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  auto rows = (*_db->connection())(select(tab.private_signature_key,
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

tc::cotask<std::optional<Crypto::PublicSignatureKey>>
LocalUserStore::findTrustchainPublicSignatureKey() const
{
  FUNC_TIMER(DB);
  TrustchainInfoTable tab{};
  auto rows = (*_db->connection())(
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

tc::cotask<void> LocalUserStore::setTrustchainPublicSignatureKey(
    Crypto::PublicSignatureKey const& sigKey)
{
  FUNC_TIMER(DB);
  TrustchainInfoTable tab{};
  (*_db->connection())(
      update(tab)
          .set(tab.trustchain_public_signature_key = sigKey.base())
          .unconditionally());
  TC_RETURN();
}

tc::cotask<std::optional<LocalUser>> LocalUserStore::findLocalUser(
    Trustchain::UserId const& userId) const
{
  auto const keys = TC_AWAIT(getDeviceKeys());
  auto const initialized = TC_AWAIT(isDeviceInitialized());
  if (!initialized)
    TC_RETURN(std::nullopt);
  auto const deviceId = TC_AWAIT(getDeviceId());
  auto const userKeys = TC_AWAIT(getUserKeyPairs());
  TC_RETURN(std::make_optional(LocalUser(userId, deviceId, keys, userKeys)));
}

tc::cotask<std::vector<Crypto::EncryptionKeyPair>>
LocalUserStore::getUserKeyPairs() const
{
  FUNC_TIMER(DB);
  UserKeysTable tab{};

  auto rows = (*_db->connection())(
      select(tab.public_encryption_key, tab.private_encryption_key)
          .from(tab)
          .unconditionally());
  std::vector<Crypto::EncryptionKeyPair> keys;
  std::transform(rows.begin(),
                 rows.end(),
                 std::back_inserter(keys),
                 [](auto&& row) -> Crypto::EncryptionKeyPair {
                   return {DataStore::extractBlob<Crypto::PublicEncryptionKey>(
                               row.public_encryption_key),
                           DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
                               row.private_encryption_key)};
                 });
  TC_RETURN(keys);
}

tc::cotask<Trustchain::DeviceId> LocalUserStore::getDeviceId() const
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  auto rows =
      (*_db->connection())(select(tab.device_id).from(tab).unconditionally());
  if (rows.empty())
    throw Errors::AssertionError("no device_id in database");
  auto const& row = rows.front();
  if (row.device_id.len == 0)
    throw Errors::AssertionError("empty device_id in database");
  TC_RETURN((DataStore::extractBlob<Trustchain::DeviceId>(row.device_id)));
}

tc::cotask<void> LocalUserStore::setDeviceInitialized()
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  (*_db->connection())(
      update(tab).set(tab.device_initialized = 1).unconditionally());
  TC_RETURN();
}

tc::cotask<void> LocalUserStore::setDeviceData(
    Trustchain::DeviceId const& deviceId, DeviceKeys const& deviceKeys)
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  (*_db->connection())(insert_into(tab).set(
      tab.device_id = deviceId.base(),
      tab.private_signature_key = deviceKeys.signatureKeyPair.privateKey.base(),
      tab.public_signature_key = deviceKeys.signatureKeyPair.publicKey.base(),
      tab.private_encryption_key =
          deviceKeys.encryptionKeyPair.privateKey.base(),
      tab.public_encryption_key = deviceKeys.encryptionKeyPair.publicKey.base(),
      tab.device_initialized = 0));
  TC_RETURN();
}

tc::cotask<bool> LocalUserStore::isDeviceInitialized() const
{
  FUNC_TIMER(DB);
  DeviceKeysTable tab{};
  auto rows = (*_db->connection())(
      select(tab.device_initialized).from(tab).unconditionally());
  if (rows.empty())
    TC_RETURN(false);
  auto const& row = rows.front();
  TC_RETURN(row.device_initialized);
}
}
