#include <Tanker/BlockGenerator.hpp>

#include <Tanker/Block.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
BlockGenerator::BlockGenerator(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& privateSignatureKey,
    Trustchain::DeviceId const& deviceId)
  : _trustchainId(trustchainId),
    _privateSignatureKey(privateSignatureKey),
    _deviceId(deviceId)
{
}

Trustchain::TrustchainId const& BlockGenerator::trustchainId() const noexcept
{
  return _trustchainId;
}

void BlockGenerator::setDeviceId(Trustchain::DeviceId const& deviceId)
{
  _deviceId = deviceId;
}

Trustchain::DeviceId const& BlockGenerator::deviceId() const
{
  return _deviceId;
}

Crypto::PrivateSignatureKey const& BlockGenerator::signatureKey() const noexcept
{
  return _privateSignatureKey;
}

std::vector<uint8_t> BlockGenerator::addUser(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKey) const
{
  return addUser3(delegation, signatureKey, encryptionKey, userEncryptionKey);
}

std::vector<uint8_t> BlockGenerator::addUser1(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey) const
{
  DeviceCreation::v1 dc1{delegation.ephemeralKeyPair.publicKey,
                         delegation.userId,
                         delegation.signature,
                         signatureKey,
                         encryptionKey};
  auto const entry =
      ClientEntry::create(_trustchainId,
                          static_cast<Crypto::Hash>(_trustchainId),
                          dc1,
                          delegation.ephemeralKeyPair.privateKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::addUser3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
          userEncryptionKeys.privateKey, encryptionKey);

  DeviceCreation::v3 dc3{delegation.ephemeralKeyPair.publicKey,
                         delegation.userId,
                         delegation.signature,
                         signatureKey,
                         encryptionKey,
                         userEncryptionKeys.publicKey,
                         sealedPrivateEncryptionKey,
                         DeviceCreation::DeviceType::Device};
  auto const entry =
      ClientEntry::create(_trustchainId,
                          static_cast<Crypto::Hash>(_trustchainId),
                          dc3,
                          delegation.ephemeralKeyPair.privateKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::addDevice(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKey) const
{
  return addDevice3(delegation, signatureKey, encryptionKey, userEncryptionKey);
}

std::vector<uint8_t> BlockGenerator::addGhostDevice(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
          userEncryptionKeys.privateKey, encryptionKey);

  DeviceCreation::v3 dc3{delegation.ephemeralKeyPair.publicKey,
                         delegation.userId,
                         delegation.signature,
                         signatureKey,
                         encryptionKey,
                         userEncryptionKeys.publicKey,
                         sealedPrivateEncryptionKey,
                         DeviceCreation::DeviceType::GhostDevice};
  auto const entry =
      ClientEntry::create(_trustchainId,
                          static_cast<Crypto::Hash>(_deviceId),
                          dc3,
                          delegation.ephemeralKeyPair.privateKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::addDevice1(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey) const
{
  DeviceCreation::v1 dc1{delegation.ephemeralKeyPair.publicKey,
                         delegation.userId,
                         delegation.signature,
                         signatureKey,
                         encryptionKey};
  auto const entry =
      ClientEntry::create(_trustchainId,
                          static_cast<Crypto::Hash>(_deviceId),
                          dc1,
                          delegation.ephemeralKeyPair.privateKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::addDevice3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
          userEncryptionKeys.privateKey, encryptionKey);

  DeviceCreation::v3 dc3{delegation.ephemeralKeyPair.publicKey,
                         delegation.userId,
                         delegation.signature,
                         signatureKey,
                         encryptionKey,
                         userEncryptionKeys.publicKey,
                         sealedPrivateEncryptionKey,
                         DeviceCreation::DeviceType::Device};
  auto const entry =
      ClientEntry::create(_trustchainId,
                          static_cast<Crypto::Hash>(_deviceId),
                          dc3,
                          delegation.ephemeralKeyPair.privateKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::revokeDevice2(
    Trustchain::DeviceId const& deviceId,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    DeviceRevocation::v2::SealedKeysForDevices const& userKeys) const
{
  DeviceRevocation2 dr2{deviceId,
                        publicEncryptionKey,
                        encryptedKeyForPreviousUserKey,
                        previousPublicEncryptionKey,
                        userKeys};
  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         dr2,
                                         _privateSignatureKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::keyPublish(
    Crypto::EncryptedSymmetricKey const& symKey,
    Trustchain::ResourceId const& resourceId,
    Trustchain::DeviceId const& recipient) const
{
  KeyPublishToDevice kp{recipient, resourceId, symKey};

  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         kp,
                                         _privateSignatureKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::keyPublishToUser(
    Crypto::SealedSymmetricKey const& symKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const
{
  KeyPublishToUser kp{recipientPublicEncryptionKey, resourceId, symKey};

  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         kp,
                                         _privateSignatureKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::keyPublishToProvisionalUser(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    ResourceId const& resourceId,
    Crypto::TwoTimesSealedSymmetricKey const& symKey) const
{
  KeyPublishToProvisionalUser kp{
      appPublicSignatureKey, resourceId, tankerPublicSignatureKey, symKey};

  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         kp,
                                         _privateSignatureKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::keyPublishToGroup(
    Crypto::SealedSymmetricKey const& symKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const
{
  KeyPublishToUserGroup kp{recipientPublicEncryptionKey, resourceId, symKey};

  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         kp,
                                         _privateSignatureKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::userGroupCreation(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    UserGroupCreation::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers) const
{
  auto const encryptedPrivateSignatureKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateSignatureKey>(
          signatureKeyPair.privateKey, publicEncryptionKey);

  UserGroupCreation ugc{signatureKeyPair.publicKey,
                        publicEncryptionKey,
                        encryptedPrivateSignatureKey,
                        sealedPrivateEncryptionKeysForUsers};
  ugc.selfSign(signatureKeyPair.privateKey);
  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         ugc,
                                         _privateSignatureKey);

  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::userGroupAddition(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    UserGroupAddition::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers) const
{
  Trustchain::GroupId const groupId{signatureKeyPair.publicKey.base()};
  UserGroupAddition uga{
      groupId, previousGroupBlockHash, sealedPrivateEncryptionKeysForUsers};
  uga.selfSign(signatureKeyPair.privateKey);

  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         uga,
                                         _privateSignatureKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::provisionalIdentityClaim(
    Trustchain::UserId const& userId,
    SecretProvisionalUser const& provisionalUser,
    Crypto::EncryptionKeyPair const& userKeyPair) const
{
  std::vector<std::uint8_t> keysToEncrypt(Crypto::PrivateEncryptionKey::arraySize * 2);

  auto it = std::copy(provisionalUser.appEncryptionKeyPair.privateKey.begin(),
                      provisionalUser.appEncryptionKeyPair.privateKey.end(),
                      keysToEncrypt.data());
  std::copy(provisionalUser.tankerEncryptionKeyPair.privateKey.begin(),
            provisionalUser.tankerEncryptionKeyPair.privateKey.end(),
            it);

  ProvisionalIdentityClaim claim{
      userId,
      provisionalUser.appSignatureKeyPair.publicKey,
      provisionalUser.tankerSignatureKeyPair.publicKey,
      userKeyPair.publicKey,
      Crypto::sealEncrypt<
          ProvisionalIdentityClaim::SealedPrivateEncryptionKeys>(
          keysToEncrypt, userKeyPair.publicKey),
  };

  claim.signWithAppKey(provisionalUser.appSignatureKeyPair.privateKey,
                       _deviceId);
  claim.signWithTankerKey(provisionalUser.tankerSignatureKeyPair.privateKey,
                          _deviceId);

  auto const entry = ClientEntry::create(_trustchainId,
                                         static_cast<Crypto::Hash>(_deviceId),
                                         claim,
                                         _privateSignatureKey);
  return Serialization::serialize(entry);
}
}
