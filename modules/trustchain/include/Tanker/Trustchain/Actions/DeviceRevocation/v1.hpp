#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp>

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
