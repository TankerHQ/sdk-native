#include <Tanker/Users/LocalUserStore.hpp>

#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/DeviceUnusable.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <range/v3/action/sort.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/set_algorithm.hpp>

TLOG_CATEGORY(LocalUserStore);

namespace Tanker::Users
{
namespace
{
constexpr auto Version = 1;

std::vector<uint8_t> serializeEncryptedDevice(DeviceData const& deviceData)
{
  std::vector<uint8_t> data(
      sizeof(uint8_t) +
      Serialization::serialized_size(deviceData.trustchainPublicKey) +
      Serialization::serialized_size(deviceData.deviceId) +
      Serialization::serialized_size(
          deviceData.deviceKeys.signatureKeyPair.privateKey) +
      Serialization::serialized_size(
          deviceData.deviceKeys.signatureKeyPair.publicKey) +
      Serialization::serialized_size(
          deviceData.deviceKeys.encryptionKeyPair.privateKey) +
      Serialization::serialized_size(
          deviceData.deviceKeys.encryptionKeyPair.publicKey) +
      Serialization::serialized_size(deviceData.userKeys));

  auto it = data.data();
  it = Serialization::serialize<uint8_t>(it, Version);
  it = Serialization::serialize(it, deviceData.trustchainPublicKey);
  it = Serialization::serialize(it, deviceData.deviceId);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.signatureKeyPair.privateKey);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.signatureKeyPair.publicKey);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.encryptionKeyPair.privateKey);
  it = Serialization::serialize(
      it, deviceData.deviceKeys.encryptionKeyPair.publicKey);
  it = Serialization::serialize(it, deviceData.userKeys);

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

  Serialization::deserialize_to(source, out.trustchainPublicKey);
  Serialization::deserialize_to(source, out.deviceId);
  Serialization::deserialize_to(source,
                                out.deviceKeys.signatureKeyPair.privateKey);
  Serialization::deserialize_to(source,
                                out.deviceKeys.signatureKeyPair.publicKey);
  Serialization::deserialize_to(source,
                                out.deviceKeys.encryptionKeyPair.privateKey);
  Serialization::deserialize_to(source,
                                out.deviceKeys.encryptionKeyPair.publicKey);
  Serialization::deserialize_to(source, out.userKeys);

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
                               DataStore::DataStore* db)
  : _userSecret(userSecret), _db(db)
{
}

tc::cotask<void> LocalUserStore::initializeDevice(
    Crypto::PublicSignatureKey const& trustchainPublicKey,
    Trustchain::DeviceId const& deviceId,
    DeviceKeys const& deviceKeys,
    std::vector<Crypto::EncryptionKeyPair> const& userKeys)
{
  TC_AWAIT(setDeviceData(
      DeviceData{trustchainPublicKey, deviceId, deviceKeys, userKeys}));
}

tc::cotask<void> LocalUserStore::putUserKeys(
    std::vector<Crypto::EncryptionKeyPair> userKeys)
{
  auto deviceData = TC_AWAIT(getDeviceData());
  if (!deviceData)
    throw Errors::AssertionError("putting user keys before initialization");

  auto proj = &Crypto::EncryptionKeyPair::publicKey;
  ranges::sort(userKeys, {}, proj);
  ranges::sort(deviceData->userKeys, {}, proj);
  deviceData->userKeys =
      ranges::views::set_union(userKeys, deviceData->userKeys, {}, proj, proj) |
      ranges::to<std::vector>;
  setDeviceData(*deviceData);
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
  auto const deviceData = TC_AWAIT(getDeviceData());
  if (!deviceData)
    TC_RETURN(std::nullopt);
  TC_RETURN(deviceData->trustchainPublicKey);
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
  auto deviceData = TC_AWAIT(getDeviceData());
  if (!deviceData)
    throw Errors::AssertionError("no user keys in database");
  TC_RETURN(std::move(deviceData->userKeys));
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

  try
  {
    auto const encryptedPayload = _db->findSerializedDevice();
    if (!encryptedPayload)
      TC_RETURN(std::nullopt);

    auto const payload =
        TC_AWAIT(DataStore::decryptValue(_userSecret, *encryptedPayload));
    auto const device = deserializeEncryptedDevice(payload);

    if (device.userKeys.empty())
      throw Errors::DeviceUnusable("no user key found in database");

    TC_RETURN(device);
  }
  catch (Errors::Exception const& e)
  {
    DataStore::handleError(e);
  }
}

tc::cotask<void> LocalUserStore::setDeviceData(DeviceData const& deviceData)
{
  FUNC_TIMER(DB);

  auto const payload = serializeEncryptedDevice(deviceData);
  auto const encryptedPayload = DataStore::encryptValue(_userSecret, payload);
  _db->putSerializedDevice(encryptedPayload);

  TC_RETURN();
}
}
