#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/Trustchain/Actions/UserGroupAddition.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace Tanker
{
class Pusher;
}

namespace Tanker::Users
{
class IUserAccessor;
class User;
}

namespace Tanker::Groups::Manager
{
static constexpr size_t MAX_GROUP_SIZE = 1000;

struct MembersToAdd
{
  std::vector<Users::User> users;
  std::vector<ProvisionalUsers::PublicUser> provisionalUsers;
};

tc::cotask<MembersToAdd> fetchFutureMembers(
    Users::IUserAccessor& userAccessor,
    std::vector<SPublicIdentity> spublicIdentities);

Trustchain::Actions::UserGroupCreation makeUserGroupCreationEntry(
    std::vector<Users::User> const& memberUsers,
    std::vector<ProvisionalUsers::PublicUser> const& memberProvisionalUsers,
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::EncryptionKeyPair const& groupEncryptionKeyPair,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey);

tc::cotask<SGroupId> create(
    Users::IUserAccessor& userAccessor,
    Pusher& pusher,
    std::vector<SPublicIdentity> const& spublicIdentities,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey);

Trustchain::Actions::UserGroupAddition makeUserGroupAdditionEntry(
    std::vector<Users::User> const& memberUsers,
    std::vector<ProvisionalUsers::PublicUser> const& memberProvisionalUsers,
    InternalGroup const& group,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey);

tc::cotask<void> updateMembers(
    Users::IUserAccessor& userAccessor,
    Pusher& pusher,
    IAccessor& groupAccessor,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey);
}
