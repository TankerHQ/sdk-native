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
        sealedPrivateEncryptionKeysForUsers,
    Crypto::Signature const& selfSignature)
  : _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _sealedPrivateSignatureKey(sealedPrivateSignatureKey),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers),
    _selfSignature(selfSignature)
{
}

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

Crypto::PublicSignatureKey const& UserGroupCreation1::publicSignatureKey() const
{
  return _publicSignatureKey;
}

Crypto::PublicEncryptionKey const& UserGroupCreation1::publicEncryptionKey()
    const
{
  return _publicEncryptionKey;
}

Crypto::SealedPrivateSignatureKey const&
UserGroupCreation1::sealedPrivateSignatureKey() const
{
  return _sealedPrivateSignatureKey;
}

auto UserGroupCreation1::sealedPrivateEncryptionKeysForUsers() const
    -> SealedPrivateEncryptionKeysForUsers const&
{
  return _sealedPrivateEncryptionKeysForUsers;
}

Crypto::Signature const& UserGroupCreation1::selfSignature() const
{
  return _selfSignature;
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

bool operator==(UserGroupCreation1 const& lhs, UserGroupCreation1 const& rhs)
{
  return std::tie(lhs.publicSignatureKey(),
                  lhs.publicEncryptionKey(),
                  lhs.sealedPrivateSignatureKey(),
                  lhs.sealedPrivateEncryptionKeysForUsers(),
                  lhs.selfSignature()) ==
         std::tie(rhs.publicSignatureKey(),
                  rhs.publicEncryptionKey(),
                  rhs.sealedPrivateSignatureKey(),
                  rhs.sealedPrivateEncryptionKeysForUsers(),
                  rhs.selfSignature());
}

bool operator!=(UserGroupCreation1 const& lhs, UserGroupCreation1 const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
