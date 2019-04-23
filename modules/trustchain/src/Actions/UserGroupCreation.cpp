#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupCreation::UserGroupCreation(
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

UserGroupCreation::UserGroupCreation(
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

Crypto::PublicSignatureKey const& UserGroupCreation::publicSignatureKey() const
{
  return _publicSignatureKey;
}

Crypto::PublicEncryptionKey const& UserGroupCreation::publicEncryptionKey()
    const
{
  return _publicEncryptionKey;
}

Crypto::SealedPrivateSignatureKey const&
UserGroupCreation::sealedPrivateSignatureKey() const
{
  return _sealedPrivateSignatureKey;
}

auto UserGroupCreation::sealedPrivateEncryptionKeysForUsers() const
    -> SealedPrivateEncryptionKeysForUsers const&
{
  return _sealedPrivateEncryptionKeysForUsers;
}

Crypto::Signature const& UserGroupCreation::selfSignature() const
{
  return _selfSignature;
}

std::vector<std::uint8_t> UserGroupCreation::signatureData() const
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

Crypto::Signature const& UserGroupCreation::selfSign(
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  if (Crypto::derivePublicKey(privateSignatureKey) != _publicSignatureKey)
  {
    throw std::runtime_error{
        "assertion failure: UserGroupCreation::selfSign: mismatching "
        "private/public signature keys"};
  }
  auto const toSign = signatureData();

  return _selfSignature = Crypto::sign(toSign, privateSignatureKey);
}

bool operator==(UserGroupCreation const& lhs, UserGroupCreation const& rhs)
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

bool operator!=(UserGroupCreation const& lhs, UserGroupCreation const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
