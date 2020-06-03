#include <Tanker/Trustchain/Actions/UserGroupAddition/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
UserGroupAddition1::UserGroupAddition1(
    TrustchainId const& trustchainId,
    GroupId const& groupId,
    Crypto::Hash const& previousGroupBlockHash,
    SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    Crypto::Hash const& author,
    Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
    Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _groupId(groupId),
    _previousGroupBlockHash(previousGroupBlockHash),
    _sealedPrivateEncryptionKeysForUsers(sealedPrivateEncryptionKeysForUsers),
    _selfSignature(Crypto::sign(signatureData(), groupPrivateSignatureKey)),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

std::vector<std::uint8_t> UserGroupAddition1::signatureData() const
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

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(
    UserGroupAddition1,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_ADDITION1_ATTRIBUTES)
}
}
}
