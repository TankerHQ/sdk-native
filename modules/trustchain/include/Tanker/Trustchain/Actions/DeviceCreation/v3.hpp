#pragma once

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
class DeviceCreation3 : private DeviceCreation1
{
  // GCC 8.1 fails to build when base_t is used...
  // Eldritch compiler bug
  using base_type = DeviceCreation1;

public:
  enum class DeviceType
  {
    Device,
    GhostDevice,
  };

  DeviceCreation3() = default;
  DeviceCreation3(
      Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
      UserId const& userId,
      Crypto::Signature const& delegationSignature,
      Crypto::PublicSignatureKey const& devicePublicSignatureKey,
      Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
      Crypto::PublicEncryptionKey const& publicUserEncryptionKey,
      Crypto::SealedPrivateEncryptionKey const& sealedPrivateUserEncryptionKey,
      DeviceType type);
  DeviceCreation3(
      Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
      UserId const& userId,
      Crypto::PublicSignatureKey const& devicePublicSignatureKey,
      Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
      Crypto::PublicEncryptionKey const& publicUserEncryptionKey,
      Crypto::SealedPrivateEncryptionKey const& sealedPrivateUserEncryptionKey,
      DeviceType type);

  static constexpr Nature nature();

  using base_type::delegationSignature;
  using base_type::ephemeralPublicSignatureKey;
  using base_type::publicEncryptionKey;
  using base_type::publicSignatureKey;
  using base_type::sign;
  using base_type::signatureData;
  using base_type::userId;

  Crypto::PublicEncryptionKey const& publicUserEncryptionKey() const;
  Crypto::SealedPrivateEncryptionKey const& sealedPrivateUserEncryptionKey()
      const;
  bool isGhostDevice() const;

private:
  Crypto::PublicEncryptionKey _publicUserEncryptionKey;
  Crypto::SealedPrivateEncryptionKey _sealedPrivateUserEncryptionKey;
  bool _isGhostDevice;

  // friend so that they can cast to the private base class
  friend bool operator==(DeviceCreation3 const& lhs,
                         DeviceCreation3 const& rhs);
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation3 const&);
  friend void to_json(nlohmann::json&, DeviceCreation3 const&);
  friend constexpr std::size_t serialized_size(DeviceCreation3 const&);
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceCreation3&);
};

bool operator==(DeviceCreation3 const& lhs, DeviceCreation3 const& rhs);
bool operator!=(DeviceCreation3 const& lhs, DeviceCreation3 const& rhs);

void from_serialized(Serialization::SerializedSource&, DeviceCreation3&);

std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation3 const&);

constexpr std::size_t serialized_size(DeviceCreation3 const&)
{
  return (Crypto::PublicSignatureKey::arraySize * 2) + UserId::arraySize +
         Crypto::Signature::arraySize +
         (Crypto::PublicEncryptionKey::arraySize * 2) +
         Crypto::SealedPrivateEncryptionKey::arraySize + sizeof(bool);
}

void to_json(nlohmann::json&, DeviceCreation3 const&);

constexpr Nature DeviceCreation3::nature()
{
  return Nature::DeviceCreation3;
}
}
}
}
