#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>

namespace Tanker::Users
{
Trustchain::ClientEntry createDeviceV1Entry(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::Hash const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey);

Trustchain::ClientEntry createNewUserEntry(
    Trustchain::TrustchainId const& trustchainId,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::ClientEntry createNewDeviceEntry(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::ClientEntry createNewGhostDeviceEntry(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::ClientEntry revokeDeviceEntry(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Crypto::PrivateSignatureKey const& signatureKey,
    Trustchain::DeviceId const& toBeRevoked,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices const&
        userKeys);
}
