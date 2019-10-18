#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceCreation2 : private DeviceCreation1
{
  // GCC 8.1 fails to build when base_t is used...
  // Eldritch compiler bug
  using base_type = DeviceCreation1;

public:
  DeviceCreation2() = default;
  DeviceCreation2(Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                  UserId const& userId,
                  Crypto::Signature const& delegationSignature,
                  Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                  Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
                  Crypto::Hash const& lastReset);
  DeviceCreation2(Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                  UserId const& userId,
                  Crypto::PublicSignatureKey const& devicePublicSignatureKey,
                  Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
                  Crypto::Hash const& lastReset);

  static constexpr Nature nature();

  using base_type::ephemeralPublicSignatureKey;
  using base_type::userId;
  using base_type::delegationSignature;
  using base_type::publicSignatureKey;
  using base_type::publicEncryptionKey;
  using base_type::signatureData;
  using base_type::sign;

  Crypto::Hash const& lastReset() const;

  // throws if !lastReset().is_null()
  DeviceCreation1 const& asDeviceCreation1() const;

private:
  Crypto::Hash _lastReset;

  friend bool operator==(DeviceCreation2 const& lhs,
                         DeviceCreation2 const& rhs);
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation2&);
  friend void to_json(nlohmann::json&, DeviceCreation2 const&);
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation2 const&);
};

bool operator==(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs);
bool operator!=(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs);

void to_json(nlohmann::json&, DeviceCreation2 const&);

void from_serialized(Serialization::SerializedSource&, DeviceCreation2&);
std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation2 const&);

constexpr std::size_t serialized_size(DeviceCreation2 const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + UserId::arraySize +
         Crypto::Signature::arraySize + Crypto::PublicEncryptionKey::arraySize +
         Crypto::Hash::arraySize;
}

constexpr Nature DeviceCreation2::nature()
{
  return Nature::DeviceCreation2;
}
}
}
}
