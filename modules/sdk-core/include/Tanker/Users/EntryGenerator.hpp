#pragma once

#include <Tanker/Crypto/EncryptedSymmetricKey.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/TwoTimesSealedSymmetricKey.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/SessionCertificate.hpp>
#include <Tanker/Verification/Verification.hpp>

namespace Tanker::Users
{
Trustchain::Actions::DeviceCreation1 createDeviceV1Action(Trustchain::TrustchainId const& trustchainId,
                                                          Crypto::Hash const& author,
                                                          Identity::Delegation const& delegation,
                                                          Crypto::PublicSignatureKey const& signatureKey,
                                                          Crypto::PublicEncryptionKey const& encryptionKey);

Trustchain::Actions::DeviceCreation3 createNewUserAction(Trustchain::TrustchainId const& trustchainId,
                                                         Identity::Delegation const& delegation,
                                                         Crypto::PublicSignatureKey const& signatureKey,
                                                         Crypto::PublicEncryptionKey const& encryptionKey,
                                                         Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::Actions::DeviceCreation3 createNewDeviceAction(Trustchain::TrustchainId const& trustchainId,
                                                           Trustchain::DeviceId const& author,
                                                           Identity::Delegation const& delegation,
                                                           Crypto::PublicSignatureKey const& signatureKey,
                                                           Crypto::PublicEncryptionKey const& encryptionKey,
                                                           Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::Actions::DeviceCreation3 createNewGhostDeviceAction(Trustchain::TrustchainId const& trustchainId,
                                                                Trustchain::DeviceId const& author,
                                                                Identity::Delegation const& delegation,
                                                                Crypto::PublicSignatureKey const& signatureKey,
                                                                Crypto::PublicEncryptionKey const& encryptionKey,
                                                                Crypto::EncryptionKeyPair const& userEncryptionKeys);

Trustchain::Actions::SessionCertificate createSessionCertificate(Trustchain::TrustchainId const& trustchainId,
                                                                 Trustchain::DeviceId const& deviceId,
                                                                 Verification::Verification const& verification,
                                                                 Crypto::PrivateSignatureKey const& signatureKey);

Trustchain::Actions::ProvisionalIdentityClaim createProvisionalIdentityClaimAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Trustchain::UserId const& userId,
    ProvisionalUsers::SecretUser const& provisionalUser,
    Crypto::EncryptionKeyPair const& userKeyPair);

Trustchain::Actions::KeyPublishToProvisionalUser createKeyPublishToProvisionalUserAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::TwoTimesSealedSymmetricKey const& symKey);

Trustchain::Actions::KeyPublishToUser createKeyPublishToUserAction(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::SealedSymmetricKey const& symKey,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey);
}
