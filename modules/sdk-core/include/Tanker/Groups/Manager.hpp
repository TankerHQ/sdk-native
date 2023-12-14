#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/IdentityUtils.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ProvisionalUserId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace Tanker::Users
{
class IUserAccessor;
class User;
}

namespace Tanker::Groups::Manager
{
static constexpr size_t MAX_GROUP_SIZE = 1000;

struct ProcessedIdentities
{
  std::vector<SPublicIdentity> spublicIdentities;
  std::vector<Identity::PublicIdentity> publicIdentities;
  PartitionedIdentities partitionedIdentities;
};

struct MembersToAdd
{
  std::vector<Users::User> users;
  std::vector<ProvisionalUsers::PublicUser> provisionalUsers;
};

tc::cotask<MembersToAdd> fetchFutureMembers(Users::IUserAccessor& userAccessor, ProcessedIdentities const& identities);

struct MembersToRemove
{
  std::vector<Trustchain::UserId> users;
  std::vector<Trustchain::ProvisionalUserId> provisionalUsers;
};

tc::cotask<MembersToRemove> fetchMembersToRemove(Users::IUserAccessor& userAccessor,
                                                 ProcessedIdentities const& identities);

Trustchain::Actions::UserGroupCreation makeUserGroupCreationAction(
    std::vector<Users::User> const& memberUsers,
    std::vector<ProvisionalUsers::PublicUser> const& memberProvisionalUsers,
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::EncryptionKeyPair const& groupEncryptionKeyPair,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey);

tc::cotask<SGroupId> create(Users::IUserAccessor& userAccessor,
                            IRequester& requester,
                            std::vector<SPublicIdentity> spublicIdentities,
                            Trustchain::TrustchainId const& trustchainId,
                            Trustchain::DeviceId const& deviceId,
                            Crypto::PrivateSignatureKey const& privateSignatureKey);

Trustchain::Actions::UserGroupAddition makeUserGroupAdditionAction(
    std::vector<Users::User> const& memberUsers,
    std::vector<ProvisionalUsers::PublicUser> const& memberProvisionalUsers,
    InternalGroup const& group,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey);

Trustchain::Actions::UserGroupRemoval makeUserGroupRemovalAction(
    std::vector<Trustchain::UserId> const& membersToRemove,
    std::vector<Trustchain::ProvisionalUserId> const& provisionalMembersToRemove,
    InternalGroup const& group,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey);

tc::cotask<void> updateMembers(Users::IUserAccessor& userAccessor,
                               IRequester& requester,
                               IAccessor& groupAccessor,
                               Trustchain::GroupId const& groupId,
                               std::vector<SPublicIdentity> spublicIdentitiesToAdd,
                               std::vector<SPublicIdentity> spublicIdentitiesToRemove,
                               Trustchain::TrustchainId const& trustchainId,
                               Trustchain::DeviceId const& deviceId,
                               Crypto::PrivateSignatureKey const& privateSignatureKey);
}
