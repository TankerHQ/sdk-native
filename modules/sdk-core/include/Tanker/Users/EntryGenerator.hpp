#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Identity/Delegation.hpp>
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
}