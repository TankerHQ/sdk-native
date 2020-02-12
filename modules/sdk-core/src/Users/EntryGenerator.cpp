#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToDevice.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

namespace Tanker::Users
{
using namespace Tanker::Trustchain;
using Trustchain::Actions::DeviceCreation;
using Trustchain::Actions::DeviceRevocation;
using Trustchain::Actions::DeviceRevocation2;

namespace
{
ClientEntry createDeviceEntry(
    TrustchainId const& trustchainId,
    Crypto::Hash const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys,
    DeviceCreation::DeviceType deviceType)
{
  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt(userEncryptionKeys.privateKey, encryptionKey);

  DeviceCreation::v3 dc3{delegation.ephemeralKeyPair.publicKey,
                         delegation.userId,
                         delegation.signature,
                         signatureKey,
                         encryptionKey,
                         userEncryptionKeys.publicKey,
                         sealedPrivateEncryptionKey,
                         deviceType};
  return ClientEntry::create(
      trustchainId, author, dc3, delegation.ephemeralKeyPair.privateKey);
}
}

ClientEntry createDeviceV1Entry(
    TrustchainId const& trustchainId,
    Crypto::Hash const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey)
{
  auto const dc1 = DeviceCreation::v1{delegation.ephemeralKeyPair.publicKey,
                                      delegation.userId,
                                      delegation.signature,
                                      signatureKey,
                                      encryptionKey};
  return ClientEntry::create(
      trustchainId, author, dc1, delegation.ephemeralKeyPair.privateKey);
}

ClientEntry createNewUserEntry(
    TrustchainId const& trustchainId,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys)
{
  return createDeviceEntry(trustchainId,
                           static_cast<Crypto::Hash>(trustchainId),
                           delegation,
                           signatureKey,
                           encryptionKey,
                           userEncryptionKeys,
                           DeviceCreation::DeviceType::GhostDevice);
}

ClientEntry createNewDeviceEntry(
    TrustchainId const& trustchainId,
    DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys)
{
  return createDeviceEntry(trustchainId,
                           static_cast<Crypto::Hash>(author),
                           delegation,
                           signatureKey,
                           encryptionKey,
                           userEncryptionKeys,
                           DeviceCreation::DeviceType::Device);
}

ClientEntry createNewGhostDeviceEntry(
    TrustchainId const& trustchainId,
    DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys)
{
  return createDeviceEntry(trustchainId,
                           static_cast<Crypto::Hash>(author),
                           delegation,
                           signatureKey,
                           encryptionKey,
                           userEncryptionKeys,
                           DeviceCreation::DeviceType::GhostDevice);
}

ClientEntry revokeDeviceEntry(
    TrustchainId const& trustchainId,
    DeviceId const& author,
    Crypto::PrivateSignatureKey const& signatureKey,
    DeviceId const& toBeRevoked,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    DeviceRevocation::v2::SealedKeysForDevices const& userKeys)
{
  DeviceRevocation2 dr2{toBeRevoked,
                        publicEncryptionKey,
                        encryptedKeyForPreviousUserKey,
                        previousPublicEncryptionKey,
                        userKeys};
  return ClientEntry::create(
      trustchainId, static_cast<Crypto::Hash>(author), dr2, signatureKey);
}

ClientEntry createProvisionalIdentityClaimEntry(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    UserId const& userId,
    ProvisionalUsers::SecretUser const& provisionalUser,
    Crypto::EncryptionKeyPair const& userKeyPair)
{
  std::vector<std::uint8_t> keysToEncrypt(
      Crypto::PrivateEncryptionKey::arraySize * 2);

  auto it = std::copy(provisionalUser.appEncryptionKeyPair.privateKey.begin(),
                      provisionalUser.appEncryptionKeyPair.privateKey.end(),
                      keysToEncrypt.data());
  std::copy(provisionalUser.tankerEncryptionKeyPair.privateKey.begin(),
            provisionalUser.tankerEncryptionKeyPair.privateKey.end(),
            it);

  Actions::ProvisionalIdentityClaim claim{
      userId,
      provisionalUser.appSignatureKeyPair.publicKey,
      provisionalUser.tankerSignatureKeyPair.publicKey,
      userKeyPair.publicKey,
      Crypto::sealEncrypt<
          Actions::ProvisionalIdentityClaim::SealedPrivateEncryptionKeys>(
          keysToEncrypt, userKeyPair.publicKey),
  };

  claim.signWithAppKey(provisionalUser.appSignatureKeyPair.privateKey,
                       deviceId);
  claim.signWithTankerKey(provisionalUser.tankerSignatureKeyPair.privateKey,
                          deviceId);

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             claim,
                             deviceSignatureKey);
}

ClientEntry createKeyPublishToProvisionalUserEntry(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    ResourceId const& resourceId,
    Crypto::TwoTimesSealedSymmetricKey const& symKey)
{
  Trustchain::Actions::KeyPublishToProvisionalUser kp{
      appPublicSignatureKey, resourceId, tankerPublicSignatureKey, symKey};

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             kp,
                             deviceSignatureKey);
}

ClientEntry createKeyPublishToUserEntry(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::SealedSymmetricKey const& symKey,
    ResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey)
{
  Trustchain::Actions::KeyPublishToUser kp{
      recipientPublicEncryptionKey, resourceId, symKey};

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             kp,
                             deviceSignatureKey);
}

ClientEntry createKeyPublishToDeviceEntry(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::EncryptedSymmetricKey const& symKey,
    ResourceId const& resourceId,
    DeviceId const& recipient)
{
  Trustchain::Actions::KeyPublishToDevice kp{recipient, resourceId, symKey};

  return ClientEntry::create(trustchainId,
                             static_cast<Crypto::Hash>(deviceId),
                             kp,
                             deviceSignatureKey);
}
}
