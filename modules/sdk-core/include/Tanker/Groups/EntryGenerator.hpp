#pragma once

#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <vector>

namespace Tanker::Groups
{
Trustchain::ClientEntry createUserGroupCreationV1Entry(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Trustchain::Actions::UserGroupCreation::v1::
        SealedPrivateEncryptionKeysForUsers const&
            sealedPrivateEncryptionKeysForUsers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::ClientEntry createUserGroupCreationV2Entry(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::PublicEncryptionKey const& groupPublicEncryptionKey,
    Trustchain::Actions::UserGroupCreation::v2::Members const& groupMembers,
    Trustchain::Actions::UserGroupCreation::v2::ProvisionalMembers const&
        groupProvisionalMembers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::ClientEntry createUserGroupAdditionV1Entry(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    Trustchain::Actions::UserGroupAddition::v1::
        SealedPrivateEncryptionKeysForUsers const&
            sealedPrivateEncryptionKeysForUsers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::ClientEntry createUserGroupAdditionV2Entry(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    std::vector<Trustchain::Actions::UserGroupAddition::v2::Member> const&
        members,
    std::vector<
        Trustchain::Actions::UserGroupAddition::v2::ProvisionalMember> const&
        provisionalMembers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);
}
