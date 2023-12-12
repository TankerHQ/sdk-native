#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceCreation1::DeviceCreation1(TrustchainId const& trustchainId,
                                 Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
                                 UserId const& userId,
                                 Crypto::Signature const& delegationSignature,
                                 Crypto::PublicSignatureKey const& publicSignatureKey,
                                 Crypto::PublicEncryptionKey const& publicEncryptionKey,
                                 Crypto::Hash const& author,
                                 Crypto::PrivateSignatureKey const& delegationPrivateSignatureKey)
  : _trustchainId(trustchainId),
    _ephemeralPublicSignatureKey(ephemeralPublicSignatureKey),
    _userId(userId),
    _delegationSignature(delegationSignature),
    _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, delegationPrivateSignatureKey))
{
}

std::vector<std::uint8_t> DeviceCreation1::delegationSignatureData() const
{
  std::vector<std::uint8_t> toSign(Crypto::PublicSignatureKey::arraySize + UserId::arraySize);

  auto it = std::copy(_ephemeralPublicSignatureKey.begin(), _ephemeralPublicSignatureKey.end(), toSign.begin());
  std::copy(_userId.begin(), _userId.end(), it);
  return toSign;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(DeviceCreation1, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V1_ATTRIBUTES)
}
}
}
