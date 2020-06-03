#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
ProvisionalIdentityClaim::ProvisionalIdentityClaim(
    UserId const& userId,
    Crypto::PublicSignatureKey const& appSignaturePublicKey,
    Crypto::PublicSignatureKey const& tankerSignaturePublicKey,
    Crypto::PublicEncryptionKey const& userPublicEncryptionKey,
    SealedPrivateEncryptionKeys const& sealedPrivateEncryptionKeys)
  : _userId(userId),
    _appSignaturePublicKey(appSignaturePublicKey),
    _tankerSignaturePublicKey(tankerSignaturePublicKey),
    _userPublicEncryptionKey(userPublicEncryptionKey),
    _sealedPrivateEncryptionKeys(sealedPrivateEncryptionKeys)
{
}

std::vector<std::uint8_t> ProvisionalIdentityClaim::signatureData(
    DeviceId const& authorId) const
{
  std::vector<std::uint8_t> signatureData(
      DeviceId::arraySize + (Crypto::PublicSignatureKey::arraySize * 2));

  auto it = std::copy(authorId.begin(), authorId.end(), signatureData.begin());
  it = std::copy(
      _appSignaturePublicKey.begin(), _appSignaturePublicKey.end(), it);
  std::copy(
      _tankerSignaturePublicKey.begin(), _tankerSignaturePublicKey.end(), it);
  return signatureData;
}

Crypto::Signature const& ProvisionalIdentityClaim::signWithAppKey(
    Crypto::PrivateSignatureKey const& privateKey, DeviceId const& authorId)
{
  auto const toSign = signatureData(authorId);

  return _authorSignatureByAppKey = Crypto::sign(toSign, privateKey);
}

Crypto::Signature const& ProvisionalIdentityClaim::signWithTankerKey(
    Crypto::PrivateSignatureKey const& privateKey, DeviceId const& authorId)
{
  auto const toSign = signatureData(authorId);

  return _authorSignatureByTankerKey = Crypto::sign(toSign, privateKey);
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    ProvisionalIdentityClaim,
    TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_IDENTITY_CLAIM_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    ProvisionalIdentityClaim,
    TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_IDENTITY_CLAIM_ATTRIBUTES)
}
}
}
