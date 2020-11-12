#include <Tanker/Trustchain/Actions/UserGroupUpdate/v1.hpp>

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
UserGroupUpdate1::UserGroupUpdate1(
    TrustchainId const& trustchainId,
    GroupId const& groupId,
    Crypto::Hash const& previousGroupBlockHash,
    Crypto::Hash const& previousKeyRotationBlockHash,
    Crypto::PublicSignatureKey const& publicSignatureKey,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
    Crypto::SealedPrivateEncryptionKey const&
        sealedPreviousPrivateEncryptionKey,
    Members const& members,
    ProvisionalMembers const& provisionalMembers,
    Crypto::Hash const& author,
    Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
    Crypto::PrivateSignatureKey const& groupPreviousPrivateSignatureKey,
    Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _groupId(groupId),
    _previousGroupBlockHash(previousGroupBlockHash),
    _previousKeyRotationBlockHash(previousKeyRotationBlockHash),
    _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _sealedPrivateSignatureKey(sealedPrivateSignatureKey),
    _sealedPreviousPrivateEncryptionKey(sealedPreviousPrivateEncryptionKey),
    _members(members),
    _provisionalMembers(provisionalMembers),
    _selfSignatureWithCurrentKey(
        Crypto::sign(signatureData(), groupPrivateSignatureKey)),
    _selfSignatureWithPreviousKey(
        Crypto::sign(signatureData(), groupPreviousPrivateSignatureKey)),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

std::vector<std::uint8_t> UserGroupUpdate1::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      GroupId::arraySize + Crypto::Hash::arraySize +
      Crypto::Hash::arraySize +
      Crypto::PublicSignatureKey::arraySize +
      Crypto::PublicEncryptionKey::arraySize +
      Crypto::SealedPrivateSignatureKey::arraySize +
      Crypto::SealedPrivateEncryptionKey::arraySize +
      (_members.size() *
       (Crypto::PublicEncryptionKey::arraySize + UserId::arraySize +
        Crypto::SealedPrivateEncryptionKey::arraySize)) +
      (_provisionalMembers.size() *
       (Crypto::PublicSignatureKey::arraySize * 2 +
        Crypto::PublicEncryptionKey::arraySize * 2 +
        Crypto::TwoTimesSealedPrivateEncryptionKey::arraySize)));
  auto it = Serialization::serialize(signatureData.data(), _groupId);
  it = Serialization::serialize(it, _previousGroupBlockHash);
  it = Serialization::serialize(it, _previousKeyRotationBlockHash);
  it = std::copy(_publicSignatureKey.begin(), _publicSignatureKey.end(), it);
  it = std::copy(_publicEncryptionKey.begin(), _publicEncryptionKey.end(), it);
  it = std::copy(
      _sealedPrivateSignatureKey.begin(), _sealedPrivateSignatureKey.end(), it);
  it = std::copy(_sealedPreviousPrivateEncryptionKey.begin(),
                 _sealedPreviousPrivateEncryptionKey.end(),
                 it);
  for (auto const& elem : _members)
  {
    it = std::copy(elem.userId().begin(), elem.userId().end(), it);
    it =
        std::copy(elem.userPublicKey().begin(), elem.userPublicKey().end(), it);
    it = std::copy(elem.encryptedPrivateEncryptionKey().begin(),
                   elem.encryptedPrivateEncryptionKey().end(),
                   it);
  }
  for (auto const& elem : _provisionalMembers)
  {
    it = std::copy(elem.appPublicSignatureKey().begin(),
                   elem.appPublicSignatureKey().end(),
                   it);
    it = std::copy(elem.tankerPublicSignatureKey().begin(),
                   elem.tankerPublicSignatureKey().end(),
                   it);
    it = std::copy(elem.appPublicEncryptionKey().begin(),
                   elem.appPublicEncryptionKey().end(),
                   it);
    it = std::copy(elem.tankerPublicEncryptionKey().begin(),
                   elem.tankerPublicEncryptionKey().end(),
                   it);
    it = std::copy(elem.encryptedPrivateEncryptionKey().begin(),
                   elem.encryptedPrivateEncryptionKey().end(),
                   it);
  }
  return signatureData;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(
    UserGroupUpdate1, TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_UPDATE_V1_ATTRIBUTES)
}
}
}
