#include <Tanker/Trustchain/Actions/UserGroupCreation/v2.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <stdexcept>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupCreation2::UserGroupCreation2(
    Crypto::PublicSignatureKey const& publicSignatureKey,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
    UserGroupMembers const& userGroupMembers,
    UserGroupProvisionalMembers const& userGroupProvisionalMembers)
  : _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _sealedPrivateSignatureKey(sealedPrivateSignatureKey),
    _userGroupMembers(userGroupMembers),
    _userGroupProvisionalMembers(userGroupProvisionalMembers),
    _selfSignature{}
{
}

std::vector<std::uint8_t> UserGroupCreation2::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      Crypto::PublicSignatureKey::arraySize +
      Crypto::PublicEncryptionKey::arraySize +
      Crypto::SealedPrivateSignatureKey::arraySize +
      (_userGroupMembers.size() *
       (Crypto::PublicEncryptionKey::arraySize + UserId::arraySize +
        Crypto::SealedPrivateEncryptionKey::arraySize)) +
      (_userGroupProvisionalMembers.size() *
       (Crypto::PublicSignatureKey::arraySize * 2 +
        Crypto::TwoTimesSealedPrivateEncryptionKey::arraySize)));
  auto it = std::copy(_publicSignatureKey.begin(),
                      _publicSignatureKey.end(),
                      signatureData.begin());
  it = std::copy(_publicEncryptionKey.begin(), _publicEncryptionKey.end(), it);
  it = std::copy(
      _sealedPrivateSignatureKey.begin(), _sealedPrivateSignatureKey.end(), it);
  for (auto const& elem : _userGroupMembers)
  {
    it = std::copy(elem.userId().begin(), elem.userId().end(), it);
    it =
        std::copy(elem.userPublicKey().begin(), elem.userPublicKey().end(), it);
    it = std::copy(elem.encryptedPrivateEncryptionKey().begin(),
                   elem.encryptedPrivateEncryptionKey().end(),
                   it);
  }
  for (auto const& elem : _userGroupProvisionalMembers)
  {
    it = std::copy(elem.appPublicSignatureKey().begin(),
                   elem.appPublicSignatureKey().end(),
                   it);
    it = std::copy(elem.tankerPublicSignatureKey().begin(),
                   elem.tankerPublicSignatureKey().end(),
                   it);
    it = std::copy(elem.encryptedPrivateEncryptionKey().begin(),
                   elem.encryptedPrivateEncryptionKey().end(),
                   it);
  }
  return signatureData;
}

Crypto::Signature const& UserGroupCreation2::selfSign(
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const toSign = signatureData();

  return _selfSignature = Crypto::sign(toSign, privateSignatureKey);
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    UserGroupCreation2,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V2_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    UserGroupCreation2,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V2_ATTRIBUTES)
}
}
}
