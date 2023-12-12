#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
ProvisionalIdentityClaim::ProvisionalIdentityClaim(TrustchainId const& trustchainId,
                                                   UserId const& userId,
                                                   Crypto::SignatureKeyPair const& appSignatureKeyPair,
                                                   Crypto::SignatureKeyPair const& tankerSignatureKeyPair,
                                                   Crypto::PublicEncryptionKey const& userPublicEncryptionKey,
                                                   SealedPrivateEncryptionKeys const& sealedPrivateEncryptionKeys,
                                                   DeviceId const& author,
                                                   Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _userId(userId),
    _appSignaturePublicKey(appSignatureKeyPair.publicKey),
    _tankerSignaturePublicKey(tankerSignatureKeyPair.publicKey),
    _authorSignatureByAppKey(Crypto::sign(signatureData(author), appSignatureKeyPair.privateKey)),
    _authorSignatureByTankerKey(Crypto::sign(signatureData(author), tankerSignatureKeyPair.privateKey)),
    _userPublicEncryptionKey(userPublicEncryptionKey),
    _sealedPrivateEncryptionKeys(sealedPrivateEncryptionKeys),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

std::vector<std::uint8_t> ProvisionalIdentityClaim::signatureData(DeviceId const& authorId) const
{
  std::vector<std::uint8_t> signatureData(DeviceId::arraySize + (Crypto::PublicSignatureKey::arraySize * 2));

  auto it = std::copy(authorId.begin(), authorId.end(), signatureData.begin());
  it = std::copy(_appSignaturePublicKey.begin(), _appSignaturePublicKey.end(), it);
  std::copy(_tankerSignaturePublicKey.begin(), _tankerSignaturePublicKey.end(), it);
  return signatureData;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(ProvisionalIdentityClaim,
                                        TANKER_TRUSTCHAIN_ACTIONS_PROVISIONAL_IDENTITY_CLAIM_ATTRIBUTES)
}
}
}
