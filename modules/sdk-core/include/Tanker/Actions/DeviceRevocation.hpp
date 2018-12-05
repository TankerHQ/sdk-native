#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace Tanker
{

// Device Revocation1:
struct DeviceRevocation1
{
  DeviceId deviceId;

  static constexpr Nature nature = Nature::DeviceRevocation;
};

constexpr std::size_t serialized_size(DeviceRevocation1 const& dr)
{
  return DeviceId::arraySize;
}

template <typename OutputIterator>
void to_serialized(OutputIterator it, DeviceRevocation1 const& dr)
{
  Serialization::serialize(it, dr.deviceId);
}

void from_serialized(Serialization::SerializedSource& ss,
                     DeviceRevocation1& dr);

void to_json(nlohmann::json& j, DeviceRevocation1 const& dr);

bool operator==(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs);
bool operator!=(DeviceRevocation1 const& lhs, DeviceRevocation1 const& rhs);

// EncryptedPrivateUserKey for DeviceRevocation2:
struct EncryptedPrivateUserKey
{
  DeviceId deviceId;
  Crypto::SealedPrivateEncryptionKey privateEncryptionKey;
};

void from_serialized(Serialization::SerializedSource& ss,
                     EncryptedPrivateUserKey& key);

std::size_t serialized_size(EncryptedPrivateUserKey const& key);

bool operator==(EncryptedPrivateUserKey const& lhs,
                EncryptedPrivateUserKey const& rhs);

bool operator!=(EncryptedPrivateUserKey const& lhs,
                EncryptedPrivateUserKey const& rhs);

bool operator<(EncryptedPrivateUserKey const& lhs,
               EncryptedPrivateUserKey const& rhs);

template <typename OutputIterator>
void to_serialized(OutputIterator it, EncryptedPrivateUserKey const& key)
{
  Serialization::serialize(it, key.deviceId);
  Serialization::serialize(it, key.privateEncryptionKey);
}

// Device Revocation2:
struct DeviceRevocation2
{
  DeviceId deviceId;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  Crypto::PublicEncryptionKey previousPublicEncryptionKey;
  Crypto::SealedPrivateEncryptionKey encryptedKeyForPreviousUserKey;
  std::vector<EncryptedPrivateUserKey> userKeys;

  static constexpr Nature nature = Nature::DeviceRevocation2;
};

std::size_t serialized_size(DeviceRevocation2 const& dr);

template <typename OutputIterator>
void to_serialized(OutputIterator it, DeviceRevocation2 const& dr)
{
  Serialization::serialize(it, dr.deviceId);
  Serialization::serialize(it, dr.publicEncryptionKey);
  Serialization::serialize(it, dr.previousPublicEncryptionKey);
  Serialization::serialize(it, dr.encryptedKeyForPreviousUserKey);
  Serialization::serialize(it, dr.userKeys);
}

void from_serialized(Serialization::SerializedSource& ss,
                     DeviceRevocation2& dr);

void to_json(nlohmann::json& j, DeviceRevocation2 const& dr);

bool operator==(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs);
bool operator!=(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs);

class DeviceRevocation
{
public:
  using variant_type = mpark::variant<DeviceRevocation1, DeviceRevocation2>;

  explicit DeviceRevocation(variant_type&&);
  explicit DeviceRevocation(variant_type const&);

  DeviceRevocation& operator=(variant_type&&);
  DeviceRevocation& operator=(variant_type const&);

  DeviceRevocation() = default;
  DeviceRevocation(DeviceRevocation const&) = default;
  DeviceRevocation(DeviceRevocation&&) = default;
  DeviceRevocation& operator=(DeviceRevocation const&) = default;
  DeviceRevocation& operator=(DeviceRevocation&&) = default;

  variant_type const& variant() const;

  Nature nature() const;
  DeviceId const& deviceId() const;

  std::vector<Index> makeIndexes() const;

private:
  variant_type _v;
};

bool operator==(DeviceRevocation const& l, DeviceRevocation const& r);
bool operator!=(DeviceRevocation const& l, DeviceRevocation const& r);

template <typename OutputIterator>
void to_serialized(OutputIterator it, DeviceRevocation const& dr)
{
  Serialization::serialize(it, dr.variant());
}

std::size_t serialized_size(DeviceRevocation const&);

void to_json(nlohmann::json& j, DeviceRevocation const& dc);
}
