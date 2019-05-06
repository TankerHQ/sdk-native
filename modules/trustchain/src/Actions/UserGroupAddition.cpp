#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupAddition::UserGroupAddition(GroupId const& groupId,
                                     Crypto::Hash const& previousGroupBlockHash,
                                     SealedPrivateEncryptionKeysForUsers const&
                                         sealedPrivateEncryptionKeysForUsers)
  : _groupId(groupId),
    _previousGroupBlockHash(previousGroupBlockHash),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers)
{
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

TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    UserGroupAddition, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION_ATTRIBUTES)

TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    UserGroupAddition, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION_ATTRIBUTES)
}
}
}
