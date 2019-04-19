#include <Tanker/Actions/DeviceRevocation.hpp>

#include <Tanker/Index.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <stdexcept>
#include <tuple>
#include <vector>

using Tanker::Trustchain::Actions::Nature;

namespace Tanker
{
void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation1& dr)
{
  Serialization::deserialize_to(ss, dr.deviceId);
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
  Serialization::deserialize_to(ss, key.deviceId);
  Serialization::deserialize_to(ss, key.privateEncryptionKey);
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

std::uint8_t* to_serialized(std::uint8_t* it,
                            EncryptedPrivateUserKey const& key)
{
  it = Serialization::serialize(it, key.deviceId);
  return Serialization::serialize(it, key.privateEncryptionKey);
}

std::size_t serialized_size(DeviceRevocation2 const& dr)
{
  return Trustchain::DeviceId::arraySize +
         Crypto::PublicEncryptionKey::arraySize * 2 +
         Crypto::SealedPrivateEncryptionKey::arraySize +
         Serialization::serialized_size(dr.userKeys);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation2 const& dr)
{
  it = Serialization::serialize(it, dr.deviceId);
  it = Serialization::serialize(it, dr.publicEncryptionKey);
  it = Serialization::serialize(it, dr.previousPublicEncryptionKey);
  it = Serialization::serialize(it, dr.encryptedKeyForPreviousUserKey);
  return Serialization::serialize(it, dr.userKeys);
}


void from_serialized(Serialization::SerializedSource& ss, DeviceRevocation2& dr)
{
  Serialization::deserialize_to(ss, dr.deviceId);
  Serialization::deserialize_to(ss, dr.publicEncryptionKey);
  Serialization::deserialize_to(ss, dr.previousPublicEncryptionKey);
  Serialization::deserialize_to(ss, dr.encryptedKeyForPreviousUserKey);
  Serialization::deserialize_to(ss, dr.userKeys);
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

Trustchain::DeviceId const& DeviceRevocation::deviceId() const
{
  return mpark::visit(
      [](auto const& a) -> Trustchain::DeviceId const& { return a.deviceId; },
      _v);
}

std::vector<Index> DeviceRevocation::makeIndexes() const
{
  return {};
}

std::size_t serialized_size(DeviceRevocation const& dr)
{
  return Serialization::serialized_size(dr.variant());
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation1 const& dr)
{
  return Serialization::serialize(it, dr.deviceId);
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation const& dr)
{
  return Serialization::serialize(it, dr.variant());
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
