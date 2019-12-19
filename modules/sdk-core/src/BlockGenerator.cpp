#include <Tanker/BlockGenerator.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

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
  auto const entry =
      Users::createDeviceV1Entry(_trustchainId,
                                 static_cast<Crypto::Hash>(_trustchainId),
                                 delegation,
                                 signatureKey,
                                 encryptionKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::addUser3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  auto const entry = Users::createNewUserEntry(_trustchainId,
                                               delegation,
                                               signatureKey,
                                               encryptionKey,
                                               userEncryptionKeys);
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

std::vector<uint8_t> BlockGenerator::addDevice1(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey) const
{
  auto const entry =
      Users::createDeviceV1Entry(_trustchainId,
                                 static_cast<Crypto::Hash>(_deviceId),
                                 delegation,
                                 signatureKey,
                                 encryptionKey);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::addDevice3(
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys) const
{
  auto const entry = Users::createNewDeviceEntry(_trustchainId,
                                                 _deviceId,
                                                 delegation,
                                                 signatureKey,
                                                 encryptionKey,
                                                 userEncryptionKeys);
  return Serialization::serialize(entry);
}

std::vector<uint8_t> BlockGenerator::revokeDevice2(
    Trustchain::DeviceId const& deviceId,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    DeviceRevocation::v2::SealedKeysForDevices const& userKeys) const
{
  auto const entry = Users::revokeDeviceEntry(_trustchainId,
                                              _deviceId,
                                              _privateSignatureKey,
                                              deviceId,
                                              publicEncryptionKey,
                                              encryptedKeyForPreviousUserKey,
                                              previousPublicEncryptionKey,
                                              userKeys);
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
}
