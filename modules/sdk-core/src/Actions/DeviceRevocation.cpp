#include <Tanker/Actions/DeviceRevocation.hpp>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <stdexcept>
#include <tuple>
#include <vector>

namespace Tanker
{
void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation1& dr)
{
  Serialization::deserialize(ss, dr.deviceId);
}

void to_json(nlohmann::json& j, DeviceRevocation1 const& dr)
{
  j["deviceId"] = dr.deviceId;
}

bool operator==(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs)
{
  return lhs.deviceId == rhs.deviceId;
}

bool operator!=(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs)
{
  return !(lhs == rhs);
}

void to_json(nlohmann::json& j, EncryptedPrivateUserKey const& epuk)
{
  j["deviceId"] = epuk.deviceId;
  j["encryptedPrivateEncryptionKey"] = epuk.privateEncryptionKey;
}

void from_serialized(Serialization::SerializedSource& ss,
                     EncryptedPrivateUserKey& key)
{
  Serialization::deserialize(ss, key.deviceId);
  Serialization::deserialize(ss, key.privateEncryptionKey);
}

std::size_t serialized_size(EncryptedPrivateUserKey const& key)
{
  return Serialization::serialized_size(key.deviceId) +
         Serialization::serialized_size(key.privateEncryptionKey);
}

bool operator==(EncryptedPrivateUserKey const& lhs,
                EncryptedPrivateUserKey const& rhs)
{
  return std::tie(lhs.deviceId, lhs.privateEncryptionKey) ==
         std::tie(rhs.deviceId, rhs.privateEncryptionKey);
}

bool operator!=(EncryptedPrivateUserKey const& lhs,
                EncryptedPrivateUserKey const& rhs)
{
  return !(lhs == rhs);
}

bool operator<(EncryptedPrivateUserKey const& lhs,
               EncryptedPrivateUserKey const& rhs)
{
  return lhs.deviceId < rhs.deviceId;
}

std::size_t serialized_size(DeviceRevocation2 const& dr)
{
  return DeviceId::arraySize + Crypto::PublicEncryptionKey::arraySize * 2 +
         Crypto::SealedPrivateEncryptionKey::arraySize +
         Serialization::serialized_size(dr.userKeys);
}

void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation2& dr)
{
  Serialization::deserialize(ss, dr.deviceId);
  Serialization::deserialize(ss, dr.publicEncryptionKey);
  Serialization::deserialize(ss, dr.previousPublicEncryptionKey);
  Serialization::deserialize(ss, dr.encryptedKeyForPreviousUserKey);
  Serialization::deserialize(ss, dr.userKeys);
}

void to_json(nlohmann::json& j, DeviceRevocation2 const& dr)
{
  j["deviceId"] = dr.deviceId;
  j["publicEncryptionKey"] = dr.publicEncryptionKey;
  j["previousPublicEncryptionKey"] = dr.previousPublicEncryptionKey;
  j["encryptedKeyForPreviousUserKey"] = dr.encryptedKeyForPreviousUserKey;
  j["userKeys"] = dr.userKeys;
}

bool operator==(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs)
{
  return std::tie(lhs.deviceId,
                  lhs.publicEncryptionKey,
                  lhs.previousPublicEncryptionKey,
                  lhs.encryptedKeyForPreviousUserKey,
                  lhs.userKeys) == std::tie(rhs.deviceId,
                                            rhs.publicEncryptionKey,
                                            rhs.previousPublicEncryptionKey,
                                            rhs.encryptedKeyForPreviousUserKey,
                                            rhs.userKeys);
}

bool operator!=(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs)
{
  return !(lhs == rhs);
}

DeviceRevocation::DeviceRevocation(variant_type&& v) : _v(std::move(v))
{
}

DeviceRevocation::DeviceRevocation(variant_type const& v) : _v(v)
{
}

DeviceRevocation& DeviceRevocation::operator=(variant_type&& v)
{
  _v = std::move(v);
  return *this;
}

DeviceRevocation& DeviceRevocation::operator=(variant_type const& v)
{
  _v = v;
  return *this;
}

auto DeviceRevocation::variant() const -> variant_type const&
{
  return _v;
}

Nature DeviceRevocation::nature() const
{
  return mpark::visit([](auto const& a) { return a.nature; }, _v);
}

DeviceId const& DeviceRevocation::deviceId() const
{
  return mpark::visit(
      [](auto const& a) -> DeviceId const& { return a.deviceId; }, _v);
}

std::vector<Index> DeviceRevocation::makeIndexes() const
{
  return {};
}

std::size_t serialized_size(DeviceRevocation const& dr)
{
  return Serialization::serialized_size(dr.variant());
}

void to_json(nlohmann::json& j, DeviceRevocation const& dc)
{
  mpark::visit([&](auto const& a) { j = a; }, dc.variant());
}

bool operator==(DeviceRevocation const& lhs, DeviceRevocation const& rhs)
{
  return lhs.variant() == rhs.variant();
}

bool operator!=(DeviceRevocation const& lhs, DeviceRevocation const& rhs)
{
  return !(lhs == rhs);
}
}
