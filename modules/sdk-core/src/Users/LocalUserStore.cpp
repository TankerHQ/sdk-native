#include <Tanker/Users/LocalUserStore.hpp>

#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/DeviceKeyStore.hpp>
#include <Tanker/DbModels/TrustchainInfo.hpp>
#include <Tanker/DbModels/UserKeys.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <sqlpp11/sqlite3/insert_or.h>

TLOG_CATEGORY(LocalUserStore);

using UserKeysTable = Tanker::DbModels::user_keys::user_keys;
using DeviceKeysTable = Tanker::DbModels::device_key_store::device_key_store;
using TrustchainInfoTable = Tanker::DbModels::trustchain_info::trustchain_info;

namespace Tanker::Users
{
namespace
{
constexpr auto Version = 1;

std::vector<uint8_t> serializeEncryptedDevice(DeviceData const& deviceData)
{
  std::vector<uint8_t> data(
      sizeof(uint8_t) + serialized_size(deviceData.deviceId) +
      serialized_size(deviceData.deviceKeys.signatureKeyPair.privateKey) +
      serialized_size(deviceData.deviceKeys.signatureKeyPair.publicKey) +
      serialized_size(deviceData.deviceKeys.encryptionKeyPair.privateKey) +
      serialized_size(deviceData.deviceKeys.encryptionKeyPair.publicKey));

  auto it = data.data();
  it = Serialization::serialize<uint8_t>(it, Version);
  it = Serialization::serialize(it, deviceData.deviceId);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.signatureKeyPair.privateKey);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.signatureKeyPair.publicKey);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.encryptionKeyPair.privateKey);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.encryptionKeyPair.publicKey);

  return data;
}

DeviceData deserializeEncryptedDevice(gsl::span<const uint8_t> payload)
{
  DeviceData out;
  Serialization::SerializedSource source(payload);

  uint8_t version;
  Serialization::deserialize_to(source, version);

  if (version != Version)
    throw Errors::formatEx(DataStore::Errc::InvalidDatabaseVersion,
                           "unsupported device storage version: {}",
                           static_cast<int>(version));

  Serialization::deserialize_to(source, out.deviceId);
  Serialization::deserialize_to(source,
                                out.deviceKeys.signatureKeyPair.privateKey);
  Serialization::deserialize_to(source,
                                out.deviceKeys.signatureKeyPair.publicKey);
  Serialization::deserialize_to(source,
                                out.deviceKeys.encryptionKeyPair.privateKey);
  Serialization::deserialize_to(source,
                                out.deviceKeys.encryptionKeyPair.publicKey);

  if (!source.eof())
  {
    throw Errors::formatEx(Serialization::Errc::TrailingInput,
                           "{} trailing bytes",
                           source.remaining_size());
  }

  return out;
}
}

LocalUserStore::LocalUserStore(Crypto::SymmetricKey const& userSecret,
                               DataStore::Database* db,
                               DataStore::DataStore* db2)
  : _userSecret(userSecret), _db(db), _db2(db2)
{
}

tc::cotask<void> LocalUserStore::initializeDevice(
    Crypto::PublicSignatureKey const& trustchainPublicKey,
    Trustchain::DeviceId const& deviceId,
    DeviceKeys const& deviceKeys,
    std::vector<Crypto::EncryptionKeyPair> const& userKeys)
{
  TC_AWAIT(_db->inTransaction([&]() -> tc::cotask<void> {
    TC_AWAIT(setDeviceData(DeviceData{deviceId, deviceKeys}));
    TC_AWAIT(setTrustchainPublicSignatureKey(trustchainPublicKey));
    TC_AWAIT(putUserKeys(userKeys));
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
  auto const deviceData = TC_AWAIT(getDeviceData());
  if (!deviceData)
    TC_RETURN(std::nullopt);
  TC_RETURN(deviceData->deviceKeys);
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

  auto keys = rows | ranges::views::transform([](auto&& row) {
                return Crypto::EncryptionKeyPair{
                    DataStore::extractBlob<Crypto::PublicEncryptionKey>(
                        row.public_encryption_key),
                    DataStore::extractBlob<Crypto::PrivateEncryptionKey>(
                        row.private_encryption_key)};
              });
  TC_RETURN(keys | ranges::to<std::vector>);
}

tc::cotask<Trustchain::DeviceId> LocalUserStore::getDeviceId() const
{
  auto const deviceData = TC_AWAIT(getDeviceData());
  if (!deviceData)
    throw Errors::AssertionError("no device_id in database");
  TC_RETURN(deviceData->deviceId);
}

tc::cotask<std::optional<DeviceData>> LocalUserStore::getDeviceData() const
{
  FUNC_TIMER(DB);

  auto const encryptedPayload = _db2->findSerializedDevice();
  if (!encryptedPayload)
    TC_RETURN(std::nullopt);

  std::vector<uint8_t> payload(EncryptorV2::decryptedSize(*encryptedPayload));
  TC_AWAIT(
      EncryptorV2::decrypt(payload.data(), _userSecret, *encryptedPayload));

  auto const device = deserializeEncryptedDevice(payload);
  TC_RETURN(device);
}

tc::cotask<void> LocalUserStore::setDeviceData(DeviceData const& deviceData)
{
  FUNC_TIMER(DB);

  auto const payload = serializeEncryptedDevice(deviceData);
  std::vector<uint8_t> encryptedPayload(
      EncryptorV2::encryptedSize(payload.size()));
  EncryptorV2::encryptSync(encryptedPayload.data(), payload, _userSecret);
  _db2->putSerializedDevice(encryptedPayload);

  TC_RETURN();
}
}
