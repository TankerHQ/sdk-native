#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker::Trustchain::Actions
{
DeviceCreation3::DeviceCreation3(TrustchainId const& trustchainId,
                                 Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                                 UserId const& userId,
                                 Crypto::Signature const& delegationSignature,
                                 Crypto::PublicSignatureKey const& publicSignatureKey,
                                 Crypto::PublicEncryptionKey const& publicEncryptionKey,
                                 Crypto::PublicEncryptionKey const& publicUserEncryptionKey,
                                 Crypto::SealedPrivateEncryptionKey const& sealedPrivateEncryptionKey,
                                 bool isGhostDevice,
                                 Crypto::Hash const& author,
                                 Crypto::PrivateSignatureKey const& delegationPrivateSignatureKey)
  : _trustchainId(trustchainId),
    _ephemeralPublicSignatureKey(ephemeralPublicSignatureKey),
    _userId(userId),
    _delegationSignature(delegationSignature),
    _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _publicUserEncryptionKey(publicUserEncryptionKey),
    _sealedPrivateUserEncryptionKey(sealedPrivateEncryptionKey),
    _isGhostDevice(isGhostDevice),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, delegationPrivateSignatureKey))
{
}

std::vector<std::uint8_t> DeviceCreation3::delegationSignatureData() const
{
  std::vector<std::uint8_t> toSign(Crypto::PublicSignatureKey::arraySize + UserId::arraySize);

  auto it = std::copy(_ephemeralPublicSignatureKey.begin(), _ephemeralPublicSignatureKey.end(), toSign.begin());
  std::copy(_userId.begin(), _userId.end(), it);
  return toSign;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(DeviceCreation3, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V3_ATTRIBUTES)
}
