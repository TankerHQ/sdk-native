#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>

#include <Tanker/Crypto/Crypto.hpp>

#include <stdexcept>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupAddition::UserGroupAddition(GroupId const& groupId,
                                     Crypto::Hash const& previousGroupBlockHash,
                                     SealedPrivateEncryptionKeysForUsers const&
                                         sealedPrivateEncryptionKeysForUsers,
                                     Crypto::Signature const& selfSignature)
  : _groupId(groupId),
    _previousGroupBlockHash(previousGroupBlockHash),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers),
    _selfSignature(selfSignature)
{
}

UserGroupAddition::UserGroupAddition(GroupId const& groupId,
                                     Crypto::Hash const& previousGroupBlockHash,
                                     SealedPrivateEncryptionKeysForUsers const&
                                         sealedPrivateEncryptionKeysForUsers)
  : _groupId(groupId),
    _previousGroupBlockHash(previousGroupBlockHash),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers)
{
}

GroupId const& UserGroupAddition::groupId() const
{
  return _groupId;
}

Crypto::Hash const& UserGroupAddition::previousGroupBlockHash() const
{
  return _previousGroupBlockHash;
}

auto UserGroupAddition::sealedPrivateEncryptionKeysForUsers() const
    -> SealedPrivateEncryptionKeysForUsers const&
{
  return _sealedPrivateEncryptionKeysForUsers;
}

Crypto::Signature const& UserGroupAddition::selfSignature() const
{
  return _selfSignature;
}

std::vector<std::uint8_t> UserGroupAddition::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      Crypto::Hash::arraySize + GroupId::arraySize +
      (_sealedPrivateEncryptionKeysForUsers.size() *
       (Crypto::PublicEncryptionKey::arraySize +
        Crypto::SealedPrivateEncryptionKey::arraySize)));

  auto it = std::copy(_groupId.begin(), _groupId.end(), signatureData.begin());
  it = std::copy(
      _previousGroupBlockHash.begin(), _previousGroupBlockHash.end(), it);
  for (auto const& elem : _sealedPrivateEncryptionKeysForUsers)
  {
    it = std::copy(elem.first.begin(), elem.first.end(), it);
    it = std::copy(elem.second.begin(), elem.second.end(), it);
  }
  return signatureData;
}

Crypto::Signature const& UserGroupAddition::selfSign(
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const toSign = signatureData();

  return _selfSignature = Crypto::sign(toSign, privateSignatureKey);
}

bool operator==(UserGroupAddition const& lhs, UserGroupAddition const& rhs)
{
  return std::tie(lhs.groupId(),
                  lhs.previousGroupBlockHash(),
                  lhs.sealedPrivateEncryptionKeysForUsers(),
                  lhs.selfSignature()) ==
         std::tie(rhs.groupId(),
                  rhs.previousGroupBlockHash(),
                  rhs.sealedPrivateEncryptionKeysForUsers(),
                  rhs.selfSignature());
}

bool operator!=(UserGroupAddition const& lhs, UserGroupAddition const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
