#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

namespace Tanker::Users
{
using Trustchain::ClientEntry;
using Trustchain::Actions::DeviceCreation;
using Trustchain::Actions::DeviceRevocation;
using Trustchain::Actions::DeviceRevocation2;

namespace
{
ClientEntry createDeviceEntry(
    Trustchain::TrustchainId const& trustchainId,
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
    Trustchain::TrustchainId const& trustchainId,
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
    Trustchain::TrustchainId const& trustchainId,
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
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
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
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
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
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Crypto::PrivateSignatureKey const& signatureKey,
    Trustchain::DeviceId const& toBeRevoked,
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
}