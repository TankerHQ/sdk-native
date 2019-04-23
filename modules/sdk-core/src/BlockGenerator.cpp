#include <Tanker/BlockGenerator.hpp>

#include <Tanker/Block.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain::Actions;
using Tanker::Trustchain::ResourceId;

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
  using Trustchain::Actions::DeviceCreation;

  return Serialization::serialize(makeBlock(
      DeviceCreation(DeviceCreation::v1(delegation.ephemeralKeyPair.publicKey,
                                        delegation.userId,
                                        delegation.signature,
                                        signatureKey,
                                        encryptionKey)),
      _trustchainId,
      delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::addUser3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  using Trustchain::Actions::DeviceCreation;

  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
          userEncryptionKeys.privateKey, encryptionKey);

  return Serialization::serialize(makeBlock(
      DeviceCreation(DeviceCreation::v3(delegation.ephemeralKeyPair.publicKey,
                                        delegation.userId,
                                        delegation.signature,
                                        signatureKey,
                                        encryptionKey,
                                        userEncryptionKeys.publicKey,
                                        sealedPrivateEncryptionKey,
                                        DeviceCreation::DeviceType::Device)),
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
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  using Trustchain::Actions::DeviceCreation;

  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
          userEncryptionKeys.privateKey, encryptionKey);

  return Serialization::serialize(
      makeBlock(DeviceCreation(DeviceCreation::v3(
                    delegation.ephemeralKeyPair.publicKey,
                    delegation.userId,
                    delegation.signature,
                    signatureKey,
                    encryptionKey,
                    userEncryptionKeys.publicKey,
                    sealedPrivateEncryptionKey,
                    DeviceCreation::DeviceType::GhostDevice)),
                _deviceId,
                delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::addDevice1(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey) const
{
  using Trustchain::Actions::DeviceCreation;

  return Serialization::serialize(makeBlock(
      DeviceCreation(DeviceCreation::v1(delegation.ephemeralKeyPair.publicKey,
                                        delegation.userId,
                                        delegation.signature,
                                        signatureKey,
                                        encryptionKey)),
      _deviceId,
      delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::addDevice3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  using Trustchain::Actions::DeviceCreation;

  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
          userEncryptionKeys.privateKey, encryptionKey);

  return Serialization::serialize(makeBlock(
      DeviceCreation(DeviceCreation::v3(delegation.ephemeralKeyPair.publicKey,
                                        delegation.userId,
                                        delegation.signature,
                                        signatureKey,
                                        encryptionKey,
                                        userEncryptionKeys.publicKey,
                                        sealedPrivateEncryptionKey,
                                        DeviceCreation::DeviceType::Device)),
      _deviceId,
      delegation.ephemeralKeyPair.privateKey));
}

std::vector<uint8_t> BlockGenerator::revokeDevice2(
    Trustchain::DeviceId const& deviceId,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices const&
        userKeys) const
{
  using namespace Trustchain::Actions;
  return Serialization::serialize(makeBlock(
      DeviceRevocation{DeviceRevocation2{deviceId,
                                         publicEncryptionKey,
                                         encryptedKeyForPreviousUserKey,
                                         previousPublicEncryptionKey,
                                         userKeys}},
      _deviceId,
      _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::keyPublish(
    Crypto::EncryptedSymmetricKey const& symKey,
    Trustchain::ResourceId const& resourceId,
    Trustchain::DeviceId const& recipient) const
{
  return Serialization::serialize(makeBlock(
      Trustchain::Actions::KeyPublishToDevice{recipient, resourceId, symKey},
      _deviceId,
      _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::keyPublishToUser(
    Crypto::SealedSymmetricKey const& symKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const
{
  return Serialization::serialize(makeBlock(
      Trustchain::Actions::KeyPublishToUser{
          recipientPublicEncryptionKey, resourceId, symKey},
      _deviceId,
      _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::keyPublishToProvisionalUser(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    ResourceId const& resourceId,
    Crypto::TwoTimesSealedSymmetricKey const& symKey) const
{
  return Serialization::serialize(makeBlock(
      KeyPublishToProvisionalUser{
          appPublicSignatureKey, resourceId, tankerPublicSignatureKey, symKey},
      _deviceId,
      this->_privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::keyPublishToGroup(
    Crypto::SealedSymmetricKey const& symKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey) const
{
  return Serialization::serialize(makeBlock(
      Trustchain::Actions::KeyPublishToUserGroup{
          recipientPublicEncryptionKey, resourceId, symKey},
      _deviceId,
      this->_privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::userGroupCreation(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Trustchain::Actions::UserGroupCreation::
        SealedPrivateEncryptionKeysForUsers const&
            sealedPrivateEncryptionKeysForUsers) const
{
  auto const encryptedPrivateSignatureKey =
      Crypto::sealEncrypt<Crypto::SealedPrivateSignatureKey>(
          signatureKeyPair.privateKey, publicEncryptionKey);

  Trustchain::Actions::UserGroupCreation ugc{
      signatureKeyPair.publicKey,
      publicEncryptionKey,
      encryptedPrivateSignatureKey,
      sealedPrivateEncryptionKeysForUsers};
  ugc.selfSign(signatureKeyPair.privateKey);

  return Serialization::serialize(
      makeBlock(ugc, _deviceId, _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::userGroupAddition(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    UserGroupAddition::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers) const
{
  Trustchain::GroupId groupId{signatureKeyPair.publicKey.base()};
  UserGroupAddition uga{
      groupId, previousGroupBlockHash, sealedPrivateEncryptionKeysForUsers};
  uga.selfSign(signatureKeyPair.privateKey);

  return Serialization::serialize(
      makeBlock(uga, _deviceId, _privateSignatureKey));
}

std::vector<uint8_t> BlockGenerator::provisionalIdentityClaim(
    Trustchain::UserId const& userId,
    SecretProvisionalUser const& provisionalUser,
    Crypto::EncryptionKeyPair const& userKeyPair) const
{
  std::vector<uint8_t> keysToEncrypt;
  keysToEncrypt.insert(keysToEncrypt.end(),
                       provisionalUser.appEncryptionKeyPair.privateKey.begin(),
                       provisionalUser.appEncryptionKeyPair.privateKey.end());
  keysToEncrypt.insert(
      keysToEncrypt.end(),
      provisionalUser.tankerEncryptionKeyPair.privateKey.begin(),
      provisionalUser.tankerEncryptionKeyPair.privateKey.end());

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

  return Serialization::serialize(
      makeBlock(claim, _deviceId, _privateSignatureKey));
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
