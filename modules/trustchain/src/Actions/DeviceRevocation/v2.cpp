#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceRevocation2::DeviceRevocation2(
    DeviceId const& deviceId,
    // avoid having both PublicEncryptionKey side by side
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& sealedKeyForPreviousUserKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    SealedKeysForDevices const& sealedUserKeysForDevices)
  : _deviceId(deviceId),
    _publicEncryptionKey(publicEncryptionKey),
    _previousPublicEncryptionKey(previousPublicEncryptionKey),
    _sealedKeyForPreviousUserKey(sealedKeyForPreviousUserKey),
    _sealedUserKeysForDevices(sealedUserKeysForDevices)
{
}

DeviceId const& DeviceRevocation2::deviceId() const
{
  return _deviceId;
}

Crypto::PublicEncryptionKey const& DeviceRevocation2::publicEncryptionKey()
    const
{
  return _publicEncryptionKey;
}

Crypto::SealedPrivateEncryptionKey const&
DeviceRevocation2::sealedKeyForPreviousUserKey() const
{
  return _sealedKeyForPreviousUserKey;
}

Crypto::PublicEncryptionKey const&
DeviceRevocation2::previousPublicEncryptionKey() const
{
  return _previousPublicEncryptionKey;
}

auto DeviceRevocation2::sealedUserKeysForDevices() const
    -> SealedKeysForDevices const&
{
  return _sealedUserKeysForDevices;
}

bool operator==(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs)
{
  return std::tie(lhs.deviceId(),
                  lhs.publicEncryptionKey(),
                  lhs.sealedKeyForPreviousUserKey(),
                  lhs.previousPublicEncryptionKey(),
                  lhs.sealedUserKeysForDevices()) ==
         std::tie(rhs.deviceId(),
                  rhs.publicEncryptionKey(),
                  rhs.sealedKeyForPreviousUserKey(),
                  rhs.previousPublicEncryptionKey(),
                  rhs.sealedUserKeysForDevices());
}

bool operator!=(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs)
{
  return !(lhs == rhs);
}

std::size_t serialized_size(DeviceRevocation2 const& dr)
{
  return Trustchain::DeviceId::arraySize +
         (Crypto::PublicEncryptionKey::arraySize * 2) +
         Crypto::SealedPrivateEncryptionKey::arraySize +
         Serialization::serialized_size(dr.sealedUserKeysForDevices());
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation2 const& dr)
{
  it = Serialization::serialize(it, dr.deviceId());
  it = Serialization::serialize(it, dr.publicEncryptionKey());
  it = Serialization::serialize(it, dr.previousPublicEncryptionKey());
  it = Serialization::serialize(it, dr.sealedKeyForPreviousUserKey());
  return Serialization::serialize(it, dr.sealedUserKeysForDevices());
}

void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation2& dr)
{
  Serialization::deserialize_to(ss, dr._deviceId);
  Serialization::deserialize_to(ss, dr._publicEncryptionKey);
  Serialization::deserialize_to(ss, dr._previousPublicEncryptionKey);
  Serialization::deserialize_to(ss, dr._sealedKeyForPreviousUserKey);
  Serialization::deserialize_to(ss, dr._sealedUserKeysForDevices);
}

void to_json(nlohmann::json& j, DeviceRevocation2 const& dr)
{
  j["deviceId"] = dr.deviceId();
  j["publicEncryptionKey"] = dr.publicEncryptionKey();
  j["previousPublicEncryptionKey"] = dr.previousPublicEncryptionKey();
  j["sealedKeyForPreviousUserKey"] = dr.sealedKeyForPreviousUserKey();
  j["sealedUserKeysForDevices"] = dr.sealedUserKeysForDevices();
}
}
}
}
