#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation2
{
public:
  using SealedKeysForDevices =
      std::vector<std::pair<DeviceId, Crypto::SealedPrivateEncryptionKey>>;

  static constexpr Nature nature();

  DeviceRevocation2() = default;
  DeviceRevocation2(DeviceId const&,
                    Crypto::PublicEncryptionKey const&,
                    Crypto::SealedPrivateEncryptionKey const&,
                    Crypto::PublicEncryptionKey const&,
                    SealedKeysForDevices const&);

  DeviceId const& deviceId() const;
  Crypto::PublicEncryptionKey const& publicEncryptionKey() const;
  Crypto::SealedPrivateEncryptionKey const& sealedKeyForPreviousUserKey() const;
  Crypto::PublicEncryptionKey const& previousPublicEncryptionKey() const;
  SealedKeysForDevices const& sealedUserKeysForDevices() const;

private:
  DeviceId _deviceId;
  Crypto::PublicEncryptionKey _publicEncryptionKey;
  Crypto::PublicEncryptionKey _previousPublicEncryptionKey;
  Crypto::SealedPrivateEncryptionKey _sealedKeyForPreviousUserKey;
  SealedKeysForDevices _sealedUserKeysForDevices;

  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceRevocation2&);
};

bool operator==(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs);
bool operator!=(DeviceRevocation2 const& lhs, DeviceRevocation2 const& rhs);

void from_serialized(Serialization::SerializedSource& ss,
                     DeviceRevocation2& dr);
std::uint8_t* to_serialized(std::uint8_t* it, DeviceRevocation2 const& dr);
std::size_t serialized_size(DeviceRevocation2 const& dr);

void to_json(nlohmann::json& j, DeviceRevocation2 const& dr);

constexpr Nature DeviceRevocation2::nature()
{
  return Nature::DeviceRevocation2;
}
}
}
}
