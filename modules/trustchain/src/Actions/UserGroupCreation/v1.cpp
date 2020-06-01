#include <Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupCreation1::UserGroupCreation1(
    TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& publicSignatureKey,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
    SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    Crypto::Hash const& author,
    Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
    Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _sealedPrivateSignatureKey(sealedPrivateSignatureKey),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers),
    _selfSignature(Crypto::sign(signatureData(), groupPrivateSignatureKey)),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

std::vector<std::uint8_t> UserGroupCreation1::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      Crypto::PublicSignatureKey::arraySize +
      Crypto::PublicEncryptionKey::arraySize +
      Crypto::SealedPrivateSignatureKey::arraySize +
      (_sealedPrivateEncryptionKeysForUsers.size() *
       (Crypto::PublicEncryptionKey::arraySize +
        Crypto::SealedPrivateEncryptionKey::arraySize)));
  auto it = std::copy(_publicSignatureKey.begin(),
                      _publicSignatureKey.end(),
                      signatureData.begin());
  it = std::copy(_publicEncryptionKey.begin(), _publicEncryptionKey.end(), it);
  it = std::copy(
      _sealedPrivateSignatureKey.begin(), _sealedPrivateSignatureKey.end(), it);
  for (auto const& elem : _sealedPrivateEncryptionKeysForUsers)
  {
    it = std::copy(elem.first.begin(), elem.first.end(), it);
    it = std::copy(elem.second.begin(), elem.second.end(), it);
  }
  return signatureData;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_PAYLOAD_SIZE(
    UserGroupCreation1,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_HASH(
    UserGroupCreation1,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION_2(
    UserGroupCreation1,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    UserGroupCreation1,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V1_ATTRIBUTES)
}
}
}
