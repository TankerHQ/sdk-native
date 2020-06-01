#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

namespace Tanker::Users
{
using namespace Tanker::Trustchain;
using Trustchain::Actions::DeviceCreation;
using Trustchain::Actions::DeviceCreation1;
using Trustchain::Actions::DeviceCreation3;
using Trustchain::Actions::DeviceRevocation;
using Trustchain::Actions::DeviceRevocation1;
using Trustchain::Actions::DeviceRevocation2;

namespace
{
DeviceCreation3 createDeviceEntry(
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

  return DeviceCreation::v3{
      trustchainId,
      delegation.ephemeralKeyPair.publicKey,
      delegation.userId,
      delegation.signature,
      signatureKey,
      encryptionKey,
      userEncryptionKeys.publicKey,
      sealedPrivateEncryptionKey,
      deviceType == DeviceCreation::DeviceType::GhostDevice,
      author,
      delegation.ephemeralKeyPair.privateKey,
  };
}
}

DeviceCreation1 createDeviceV1Entry(
    TrustchainId const& trustchainId,
    Crypto::Hash const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey)
{
  return DeviceCreation::v1{trustchainId,
                            delegation.ephemeralKeyPair.publicKey,
                            delegation.userId,
                            delegation.signature,
                            signatureKey,
                            encryptionKey,
                            author,
                            delegation.ephemeralKeyPair.privateKey};
}

DeviceCreation3 createNewUserEntry(
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

DeviceCreation3 createNewDeviceEntry(
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

DeviceCreation3 createNewGhostDeviceEntry(
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

DeviceRevocation2 revokeDeviceEntry(
    TrustchainId const& trustchainId,
    DeviceId const& author,
    Crypto::PrivateSignatureKey const& signatureKey,
    DeviceId const& toBeRevoked,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    DeviceRevocation::v2::SealedKeysForDevices const& userKeys)
{
  return DeviceRevocation2{
      trustchainId,
      toBeRevoked,
      publicEncryptionKey,
      previousPublicEncryptionKey,
      encryptedKeyForPreviousUserKey,
      userKeys,
      static_cast<Crypto::Hash>(author),
      signatureKey,
  };
}

DeviceRevocation1 revokeDeviceV1Entry(
    TrustchainId const& trustchainId,
    DeviceId const& author,
    Crypto::PrivateSignatureKey const& signatureKey,
    DeviceId const& toBeRevoked)
{
  return DeviceRevocation1{
      trustchainId,
      toBeRevoked,
      static_cast<Crypto::Hash>(author),
      signatureKey,
  };
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
}
