#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>

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
#define TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V2_ATTRIBUTES           \
  (deviceId, DeviceId), (publicEncryptionKey, Crypto::PublicEncryptionKey), \
      (previousPublicEncryptionKey, Crypto::PublicEncryptionKey),           \
      (sealedKeyForPreviousUserKey, Crypto::SealedPrivateEncryptionKey),    \
      (sealedUserKeysForDevices, SealedKeysForDevices)

class DeviceRevocation2
{
public:
  using SealedKeysForDevices =
      std::vector<std::pair<DeviceId, Crypto::SealedPrivateEncryptionKey>>;

  TANKER_IMMUTABLE_DATA_TYPE_IMPLEMENTATION(
      DeviceRevocation2,
      TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V2_ATTRIBUTES)

public:
  static constexpr Nature nature();

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceRevocation2&);
};

constexpr Nature DeviceRevocation2::nature()
{
  return Nature::DeviceRevocation2;
}

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceRevocation2)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceRevocation2)
}
}
}
