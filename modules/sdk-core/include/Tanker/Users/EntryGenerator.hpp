#pragma once

#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/SessionCertificate.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Unlock/Verification.hpp>

namespace Tanker::Users
{
Trustchain::Actions::DeviceCreation1 createDeviceV1Action(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::Hash const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey);

Trustchain::Actions::DeviceCreation3 createNewUserAction(
    Trustchain::TrustchainId const& trustchainId,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::Actions::DeviceCreation3 createNewDeviceAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::Actions::DeviceCreation3 createNewGhostDeviceAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::Actions::DeviceRevocation2 createRevokeDeviceAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Crypto::PrivateSignatureKey const& signatureKey,
    Trustchain::DeviceId const& toBeRevoked,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::SealedPrivateEncryptionKey const& encryptedKeyForPreviousUserKey,
    Crypto::PublicEncryptionKey const& previousPublicEncryptionKey,
    Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices const&
        userKeys);

Trustchain::Actions::DeviceRevocation1 createRevokeDeviceV1Action(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& author,
    Crypto::PrivateSignatureKey const& signatureKey,
    Trustchain::DeviceId const& toBeRevoked);

Trustchain::Actions::SessionCertificate createSessionCertificate(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Unlock::Verification const& verification,
    Crypto::PrivateSignatureKey const& signatureKey);

Trustchain::Actions::ProvisionalIdentityClaim
createProvisionalIdentityClaimAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Trustchain::UserId const& userId,
    ProvisionalUsers::SecretUser const& provisionalUser,
    Crypto::EncryptionKeyPair const& userKeyPair);

Trustchain::Actions::KeyPublishToProvisionalUser
createKeyPublishToProvisionalUserAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::TwoTimesSealedSymmetricKey const& symKey);

Trustchain::Actions::KeyPublishToUser createKeyPublishToUserAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::SealedSymmetricKey const& symKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey);
}
