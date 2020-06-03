#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>

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
DeviceRevocation2::DeviceRevocation2(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& sealedKeyForPreviousUserKey,
    SealedKeysForDevices const& sealedUserKeysForDevices,
    Crypto::Hash const& author,
    Crypto::PrivateSignatureKey const& authorPrivateSignatureKey)
  : _trustchainId(trustchainId),
    _deviceId(deviceId),
    _publicEncryptionKey(publicEncryptionKey),
    _previousPublicEncryptionKey(previousPublicEncryptionKey),
    _sealedKeyForPreviousUserKey(sealedKeyForPreviousUserKey),
    _sealedUserKeysForDevices(sealedUserKeysForDevices),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, authorPrivateSignatureKey))
{
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(
    DeviceRevocation2,
    TANKER_TRUSTCHAIN_ACTIONS_DEVICE_REVOCATION_V2_ATTRIBUTES)
}
}
}
