#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SealedSymmetricKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Users/User.hpp>

#include <vector>

namespace Tanker::Groups
{
Trustchain::Actions::UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers generateGroupKeysForUsers1(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey, std::vector<Users::User> const& users);

Trustchain::Actions::UserGroupCreation::v2::Members generateGroupKeysForUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey, std::vector<Users::User> const& users);

Trustchain::Actions::UserGroupCreation::v2::Members generateGroupKeysForUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<Trustchain::Actions::RawUserGroupMember2> const& users);

Trustchain::Actions::UserGroupCreation::v2::ProvisionalMembers generateGroupKeysForProvisionalUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<ProvisionalUsers::PublicUser> const& users);

Trustchain::Actions::UserGroupCreation::v3::ProvisionalMembers generateGroupKeysForProvisionalUsers3(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<ProvisionalUsers::PublicUser> const& users);

Trustchain::Actions::UserGroupCreation::v3::ProvisionalMembers generateGroupKeysForProvisionalUsers3(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<Trustchain::Actions::RawUserGroupProvisionalMember3> const& users);

Trustchain::Actions::UserGroupCreation1 createUserGroupCreationV1Action(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Trustchain::Actions::UserGroupCreation::v1::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::Actions::UserGroupCreation2 createUserGroupCreationV2Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::PublicEncryptionKey const& groupPublicEncryptionKey,
    Trustchain::Actions::UserGroupCreation::v2::Members const& groupMembers,
    Trustchain::Actions::UserGroupCreation::v2::ProvisionalMembers const& groupProvisionalMembers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::Actions::UserGroupCreation3 createUserGroupCreationV3Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::PublicEncryptionKey const& groupPublicEncryptionKey,
    Trustchain::Actions::UserGroupCreation::v2::Members const& groupMembers,
    Trustchain::Actions::UserGroupCreation::v3::ProvisionalMembers const& groupProvisionalMembers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::Actions::UserGroupAddition1 createUserGroupAdditionV1Action(
    Crypto::SignatureKeyPair const& signatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    Trustchain::Actions::UserGroupAddition::v1::SealedPrivateEncryptionKeysForUsers const&
        sealedPrivateEncryptionKeysForUsers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::Actions::UserGroupAddition2 createUserGroupAdditionV2Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    std::vector<Trustchain::Actions::UserGroupAddition::v2::Member> const& members,
    std::vector<Trustchain::Actions::UserGroupAddition::v2::ProvisionalMember> const& provisionalMembers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::Actions::UserGroupAddition3 createUserGroupAdditionV3Action(
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::Hash const& previousGroupBlockHash,
    std::vector<Trustchain::Actions::UserGroupAddition::v2::Member> const& members,
    std::vector<Trustchain::Actions::UserGroupAddition::v3::ProvisionalMember> const& provisionalMembers,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

Trustchain::Actions::KeyPublishToUserGroup createKeyPublishToGroupAction(
    Crypto::SealedSymmetricKey const& symKey,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);
}
