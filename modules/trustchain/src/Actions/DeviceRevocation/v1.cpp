#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceRevocation1::DeviceRevocation1(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::Hash const& author,
    Crypto::PrivateSignatureKey const& authorPrivateSignatureKey)
  : _trustchainId(trustchainId),
    _deviceId(deviceId),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, authorPrivateSignatureKey))
{
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(
    DeviceRevocation1,
    TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V1_ATTRIBUTES)
}
}
}
