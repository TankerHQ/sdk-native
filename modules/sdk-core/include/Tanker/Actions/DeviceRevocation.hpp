#pragma once

#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Serialization/serialized_size.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <gsl-lite.hpp>
#include <mpark/variant.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace Tanker
{
struct DeviceRevocation1
{
  DeviceId deviceId;

  static constexpr Nature nature = Nature::DeviceRevocation;
};

constexpr std::size_t serialized_size(DeviceRevocation1 const& dr)
{
  return DeviceId::arraySize;
}

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation1 const& dr);

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

void to_json(nlohmann::json& j, EncryptedPrivateUserKey const& epuk);

void from_serialized(Serialization::SerializedSource& ss,
                     EncryptedPrivateUserKey& key);

constexpr std::size_t serialized_size(EncryptedPrivateUserKey const& key)
{
  return Serialization::serialized_size(key.deviceId) +
         Serialization::serialized_size(key.privateEncryptionKey);
}

bool operator==(EncryptedPrivateUserKey const& lhs,
                EncryptedPrivateUserKey const& rhs);

bool operator!=(EncryptedPrivateUserKey const& lhs,
                EncryptedPrivateUserKey const& rhs);

bool operator<(EncryptedPrivateUserKey const& lhs,
               EncryptedPrivateUserKey const& rhs);

std::uint8_t* to_serialized(std::uint8_t* it,
                            EncryptedPrivateUserKey const& key);

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

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation2 const& dr);

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

std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation const& dr);
std::size_t serialized_size(DeviceRevocation const&);

void to_json(nlohmann::json& j, DeviceRevocation const& dc);
}
