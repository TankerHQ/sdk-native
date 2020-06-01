#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
std::vector<std::uint8_t> DeviceCreation3::signatureData() const
{
  std::vector<std::uint8_t> toSign(Crypto::PublicSignatureKey::arraySize +
                                   UserId::arraySize);

  auto it = std::copy(_ephemeralPublicSignatureKey.begin(),
                      _ephemeralPublicSignatureKey.end(),
                      toSign.begin());
  std::copy(_userId.begin(), _userId.end(), it);
  return toSign;
}

Crypto::Signature const& DeviceCreation3::sign(
    Crypto::PrivateSignatureKey const& key)
{
  auto const toSign = signatureData();
  return _delegationSignature = Crypto::sign(toSign, key);
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    DeviceCreation3, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V3_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    DeviceCreation3, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V3_ATTRIBUTES)
}
}
}
