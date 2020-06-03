#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Json.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
#define TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V1_ATTRIBUTES \
  (deviceId, DeviceId)

class DeviceRevocation1
{
public:
  TANKER_IMMUTABLE_ACTION_IMPLEMENTATION(
      DeviceRevocation1,
      TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V1_ATTRIBUTES)

public:
  DeviceRevocation1(
      TrustchainId const& trustchainId,
      DeviceId const& deviceId,
      Crypto::Hash const& author,
      Crypto::PrivateSignatureKey const& authorPrivateSignatureKey);

private:
  friend void from_serialized(Serialization::SerializedSource&,
                              DeviceRevocation1&);
};

TANKER_TRUSTCHAIN_ACTION_DECLARE_SERIALIZATION(DeviceRevocation1)
TANKER_TRUSTCHAIN_ACTION_DECLARE_TO_JSON(DeviceRevocation1)
}
}
}
