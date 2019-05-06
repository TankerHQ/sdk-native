#include <Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>

#include <stdexcept>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupCreation1::UserGroupCreation1(
    Crypto::PublicSignatureKey const& publicSignatureKey,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
    SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers)
  : _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _sealedPrivateSignatureKey(sealedPrivateSignatureKey),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers),
    _selfSignature{}
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

Crypto::Signature const& UserGroupCreation1::selfSign(
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const toSign = signatureData();

  return _selfSignature = Crypto::sign(toSign, privateSignatureKey);
}
}
}
}
