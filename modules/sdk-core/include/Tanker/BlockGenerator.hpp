#pragma once

#include <Tanker/Block.hpp>
#include <Tanker/Crypto/BasicHash.hpp>
#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
#include <Tanker/SecretProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Identity
{
struct Delegation;
}

class BlockGenerator
{
public:
  BlockGenerator(Trustchain::TrustchainId const& trustchainId,
                 Crypto::PrivateSignatureKey const& privateSignatureKey,
                 Trustchain::DeviceId const& deviceId);

  Trustchain::TrustchainId const& trustchainId() const noexcept;
  Crypto::PrivateSignatureKey const& signatureKey() const noexcept;

  void setDeviceId(Trustchain::DeviceId const& deviceId);
  Trustchain::DeviceId const& deviceId() const;

  std::vector<uint8_t> addUser(
      Identity::Delegation const& delegation,
      Crypto::PublicSignatureKey const& signatureKey,
      Crypto::PublicEncryptionKey const& encryptionKey,
      Crypto::EncryptionKeyPair const& userEncryptionKey) const;
  std::vector<uint8_t> addUser1(
      Identity::Delegation const& delegation,
      Crypto::PublicSignatureKey const& signatureKey,
      Crypto::PublicEncryptionKey const& encryptionKey) const;
  std::vector<uint8_t> addUser3(
      Identity::Delegation const& delegation,
      Crypto::PublicSignatureKey const& signatureKey,
      Crypto::PublicEncryptionKey const& encryptionKey,
      Crypto::EncryptionKeyPair const& userEncryptionKey) const;

  std::vector<uint8_t> addDevice(
      Identity::Delegation const& delegation,
      Crypto::PublicSignatureKey const& signatureKey,
      Crypto::PublicEncryptionKey const& encryptionKey,
      Crypto::EncryptionKeyPair const& userEncryptionKey) const;
  std::vector<uint8_t> addDevice1(
      Identity::Delegation const& delegation,
      Crypto::PublicSignatureKey const& signatureKey,
      Crypto::PublicEncryptionKey const& encryptionKey) const;
  std::vector<uint8_t> addDevice3(
      Identity::Delegation const& delegation,
      Crypto::PublicSignatureKey const& signatureKey,
      Crypto::PublicEncryptionKey const& encryptionKey,
      Crypto::EncryptionKeyPair const& userEncryptionKey) const;

  std::vector<uint8_t> addGhostDevice(
      Identity::Delegation const& delegation,
      Crypto::PublicSignatureKey const& signatureKey,
      Crypto::PublicEncryptionKey const& encryptionKey,
      Crypto::EncryptionKeyPair const& userEncryptionKey) const;

  std::vector<uint8_t> revokeDevice2(
      Trustchain::DeviceId const& deviceId,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
      Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
      Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices const&
          userKeys) const;

  std::vector<uint8_t> keyPublish(Crypto::EncryptedSymmetricKey const& symKey,
                                  Trustchain::ResourceId const& resourceId,
                                  Trustchain::DeviceId const& recipient) const;

  std::vector<uint8_t> keyPublishToUser(
      Crypto::SealedSymmetricKey const& symKey,
      Trustchain::ResourceId const& resourceId,
      Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const;

  std::vector<uint8_t> keyPublishToProvisionalUser(
      Crypto::PublicSignatureKey const& appPublicSignatureKey,
      Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
      Trustchain::ResourceId const& resourceId,
      Crypto::TwoTimesSealedSymmetricKey const& symKey) const;

  std::vector<uint8_t> keyPublishToGroup(
      Crypto::SealedSymmetricKey const& symKey,
      Trustchain::ResourceId const& resourceId,
      Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const;

  std::vector<uint8_t> userGroupCreation(
      Crypto::SignatureKeyPair const& signatureKeyPair,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Trustchain::Actions::UserGroupCreation::v1::
          SealedPrivateEncryptionKeysForUsers const&
              sealedPrivateEncryptionKeysForUsers) const;

  std::vector<uint8_t> userGroupCreation2(
      Crypto::SignatureKeyPair const& signatureKeyPair,
      Crypto::PublicEncryptionKey const& publicEncryptionKey,
      Trustchain::Actions::UserGroupCreation::v2::Members const& groupMembers,
      Trustchain::Actions::UserGroupCreation::v2::ProvisionalMembers const&
          groupProvisionalMembers) const;

  std::vector<uint8_t> userGroupAddition(
      Crypto::SignatureKeyPair const& signatureKeyPair,
      Crypto::Hash const& previousGroupBlockHash,
      Trustchain::Actions::UserGroupAddition::v1::
          SealedPrivateEncryptionKeysForUsers const&
              sealedPrivateEncryptionKeysForUsers) const;

  std::vector<uint8_t> userGroupAddition2(
      Crypto::SignatureKeyPair const& signatureKeyPair,
      Crypto::Hash const& previousGroupBlockHash,
      std::vector<Trustchain::Actions::UserGroupAddition::v2::Member> const&
          members,
      std::vector<
          Trustchain::Actions::UserGroupAddition::v2::ProvisionalMember> const&
          provisionalMembers) const;

  std::vector<uint8_t> provisionalIdentityClaim(
      Trustchain::UserId const& userId,
      SecretProvisionalUser const& provisionalUser,
      Crypto::EncryptionKeyPair const& userKeyPair) const;

private:
  Trustchain::TrustchainId _trustchainId;
  Crypto::PrivateSignatureKey _privateSignatureKey;
  Trustchain::DeviceId _deviceId;
};
}
