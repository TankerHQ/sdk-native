#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceCreation1::DeviceCreation1(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey)
  : _ephemeralPublicSignatureKey(ephemeralPublicSignatureKey),
    _userId(userId),
    _publicSignatureKey(devicePublicSignatureKey),
    _publicEncryptionKey(devicePublicEncryptionKey)
{
}

std::vector<std::uint8_t> DeviceCreation1::signatureData() const
{
  std::vector<std::uint8_t> toSign(Crypto::PublicSignatureKey::arraySize +
                                   UserId::arraySize);

  auto it = std::copy(_ephemeralPublicSignatureKey.begin(),
                      _ephemeralPublicSignatureKey.end(),
                      toSign.begin());
  std::copy(_userId.begin(), _userId.end(), it);
  return toSign;
}

Crypto::Signature const& DeviceCreation1::sign(
    Crypto::PrivateSignatureKey const& key)
{
  auto const toSign = signatureData();
  return _delegationSignature = Crypto::sign(toSign, key);
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    DeviceCreation1, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V1_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    DeviceCreation1, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V1_ATTRIBUTES)
}
}
}
