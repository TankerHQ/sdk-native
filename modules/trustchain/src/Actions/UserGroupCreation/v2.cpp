#include <Tanker/Trustchain/Actions/UserGroupCreation/v2.hpp>

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
UserGroupCreation2::UserGroupCreation2(
    TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& publicSignatureKey,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateSignatureKey const& sealedPrivateSignatureKey,
    Members const& members,
    ProvisionalMembers const& provisionalMembers,
    Crypto::Hash const& author,
    Crypto::PrivateSignatureKey const& groupPrivateSignatureKey,
    Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _sealedPrivateSignatureKey(sealedPrivateSignatureKey),
    _members(members),
    _provisionalMembers(provisionalMembers),
    _selfSignature(Crypto::sign(signatureData(), groupPrivateSignatureKey)),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

std::vector<std::uint8_t> UserGroupCreation2::signatureData() const
{
  std::vector<std::uint8_t> signatureData(
      Crypto::PublicSignatureKey::arraySize +
      Crypto::PublicEncryptionKey::arraySize +
      Crypto::SealedPrivateSignatureKey::arraySize +
      (_members.size() *
       (Crypto::PublicEncryptionKey::arraySize + UserId::arraySize +
        Crypto::SealedPrivateEncryptionKey::arraySize)) +
      (_provisionalMembers.size() *
       (Crypto::PublicSignatureKey::arraySize * 2 +
        Crypto::TwoTimesSealedPrivateEncryptionKey::arraySize)));
  auto it = std::copy(_publicSignatureKey.begin(),
                      _publicSignatureKey.end(),
                      signatureData.begin());
  it = std::copy(_publicEncryptionKey.begin(), _publicEncryptionKey.end(), it);
  it = std::copy(
      _sealedPrivateSignatureKey.begin(), _sealedPrivateSignatureKey.end(), it);
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
    it = std::copy(elem.encryptedPrivateEncryptionKey().begin(),
                   elem.encryptedPrivateEncryptionKey().end(),
                   it);
  }
  return signatureData;
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(
    UserGroupCreation2,
    TANKER_TRUSTCHAIN_ACTIONS_USER_GROUP_CREATION_V2_ATTRIBUTES)
}
}
}
