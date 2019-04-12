#include <Tanker/BlockGenerator.hpp>

#include <Tanker/Action.hpp>
#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/DeviceRevocation.hpp>
#include <Tanker/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Actions/KeyPublishToUser.hpp>
#include <Tanker/Actions/KeyPublishToUserGroup.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <stdexcept>

namespace Tanker
{
BlockGenerator::BlockGenerator(
    TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& privateSignatureKey,
    DeviceId const& deviceId)
  : _trustchainId(trustchainId),
    _privateSignatureKey(privateSignatureKey),
    _deviceId(deviceId)
{
}

TrustchainId const& BlockGenerator::trustchainId() const noexcept
{
  return _trustchainId;
}

void BlockGenerator::setDeviceId(DeviceId const& deviceId)
{
  _deviceId = deviceId;
}

DeviceId const& BlockGenerator::deviceId() const
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
  return Serialization::serialize(makeBlock(
      DeviceCreation::createV1(delegation, signatureKey, encryptionKey),
      _trustchainId,
      delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::addUser3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKey) const
{
  return Serialization::serialize(makeBlock(
      DeviceCreation::createV3(
          delegation, signatureKey, encryptionKey, userEncryptionKey, false),
      _trustchainId,
      delegation.ephemeralKeyPair.privateKey));
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
    Crypto::EncryptionKeyPair const& userEncryptionKey) const
{
  return Serialization::serialize(makeBlock(
      DeviceCreation::createV3(
          delegation, signatureKey, encryptionKey, userEncryptionKey, true),
      _deviceId,
      delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::addDevice1(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey) const
{
  return Serialization::serialize(makeBlock(
      DeviceCreation::createV1(delegation, signatureKey, encryptionKey),
      _deviceId,
      delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::addDevice3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKey) const
{
  return Serialization::serialize(makeBlock(
      DeviceCreation::createV3(
          delegation, signatureKey, encryptionKey, userEncryptionKey, false),
      _deviceId,
      delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::revokeDevice2(
    DeviceId const& deviceId,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    std::vector<EncryptedPrivateUserKey> const& userKeys) const
{
  return Serialization::serialize(makeBlock(
      DeviceRevocation{DeviceRevocation2{deviceId,
                                         publicEncryptionKey,
                                         previousPublicEncryptionKey,
                                         encryptedKeyForPreviousUserKey,
                                         userKeys}},
      _deviceId,
      _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::keyPublish(
    Crypto::EncryptedSymmetricKey const& symKey,
    Crypto::Mac const& mac,
    DeviceId const& recipient) const
{
  return Serialization::serialize(
      makeBlock(KeyPublishToDevice{recipient, mac, symKey},
                _deviceId,
                _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::keyPublishToUser(
    Crypto::SealedSymmetricKey const& symKey,
    Crypto::Mac const& mac,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const
{
  return Serialization::serialize(
      makeBlock(KeyPublishToUser{recipientPublicEncryptionKey, mac, symKey},
                _deviceId,
                _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::keyPublishToGroup(
    Crypto::SealedSymmetricKey const& symKey,
    Crypto::Mac const& mac,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const
{
  return Serialization::serialize(makeBlock(
      KeyPublishToUserGroup{recipientPublicEncryptionKey, mac, symKey},
      _deviceId,
      this->_privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::userGroupCreation(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    UserGroupCreation::GroupEncryptedKeys const&
        encryptedGroupPrivateEncryptionKeysForUsers) const
{
  auto const encryptedPrivateSignatureKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateSignatureKey>(
          signatureKeyPair.privateKey, publicEncryptionKey);

  std::vector<uint8_t> toSign;
  toSign.insert(toSign.end(),
                signatureKeyPair.publicKey.begin(),
                signatureKeyPair.publicKey.end());
  toSign.insert(
      toSign.end(), publicEncryptionKey.begin(), publicEncryptionKey.end());
  toSign.insert(toSign.end(),
                encryptedPrivateSignatureKey.begin(),
                encryptedPrivateSignatureKey.end());
  for (auto const& elem : encryptedGroupPrivateEncryptionKeysForUsers)
  {
    toSign.insert(toSign.end(),
                  elem.publicUserEncryptionKey.begin(),
                  elem.publicUserEncryptionKey.end());
    toSign.insert(toSign.end(),
                  elem.encryptedGroupPrivateEncryptionKey.begin(),
                  elem.encryptedGroupPrivateEncryptionKey.end());
  }
  auto const selfSignature = Crypto::sign(toSign, signatureKeyPair.privateKey);

  return Serialization::serialize(
      makeBlock(UserGroupCreation{signatureKeyPair.publicKey,
                                  publicEncryptionKey,
                                  encryptedPrivateSignatureKey,
                                  encryptedGroupPrivateEncryptionKeysForUsers,
                                  selfSignature},
                _deviceId,
                _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::userGroupAddition(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::Hash const& previousGroupBlock,
    UserGroupCreation::GroupEncryptedKeys const&
        encryptedGroupPrivateEncryptionKeysForUsers) const
{
  std::vector<uint8_t> toSign;
  toSign.insert(toSign.end(),
                signatureKeyPair.publicKey.begin(),
                signatureKeyPair.publicKey.end());
  toSign.insert(
      toSign.end(), previousGroupBlock.begin(), previousGroupBlock.end());
  for (auto const& elem : encryptedGroupPrivateEncryptionKeysForUsers)
  {
    toSign.insert(toSign.end(),
                  elem.publicUserEncryptionKey.begin(),
                  elem.publicUserEncryptionKey.end());
    toSign.insert(toSign.end(),
                  elem.encryptedGroupPrivateEncryptionKey.begin(),
                  elem.encryptedGroupPrivateEncryptionKey.end());
  }
  auto const selfSignature = Crypto::sign(toSign, signatureKeyPair.privateKey);

  return Serialization::serialize(
      makeBlock(UserGroupAddition{GroupId{signatureKeyPair.publicKey},
                                  previousGroupBlock,
                                  encryptedGroupPrivateEncryptionKeysForUsers,
                                  selfSignature},
                _deviceId,
                _privateSignatureKey));
}

template <typename T, typename U>
Block BlockGenerator::makeBlock(
    Nature nature,
    T const& action,
    Crypto::BasicHash<U> const& parentHash,
    Crypto::PrivateSignatureKey const& privateSignatureKey) const
{
  if (parentHash.is_null())
    throw std::runtime_error("parentHash is null");

  Block ret;
  ret.trustchainId = _trustchainId;
  ret.author = Crypto::Hash{parentHash};
  ret.nature = nature;
  ret.payload = Serialization::serialize(action);
  ret.signature = Crypto::sign(ret.hash(), privateSignatureKey);

  return ret;
}

template <typename T, typename U>
Block BlockGenerator::makeBlock(
    T const& action,
    Crypto::BasicHash<U> const& parentHash,
    Crypto::PrivateSignatureKey const& privateSignatureKey) const
{
  return makeBlock(action.nature(), action, parentHash, privateSignatureKey);
}
}
