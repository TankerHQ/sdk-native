#pragma once

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/PublicProvisionalUser.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/UserAccessor.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace Tanker
{
namespace Groups
{
namespace Manager
{
static constexpr size_t MAX_GROUP_SIZE = 1000;

struct MembersToAdd
{
  std::vector<User> users;
  std::vector<PublicProvisionalUser> provisionalUsers;
};

tc::cotask<MembersToAdd> fetchFutureMembers(
    UserAccessor& userAccessor, std::vector<SPublicIdentity> spublicIdentities);

tc::cotask<std::vector<uint8_t>> generateCreateGroupBlock(
    std::vector<User> const& memberUsers,
    std::vector<PublicProvisionalUser> const& memberProvisionalUsers,
    BlockGenerator const& blockGenerator,
    Crypto::SignatureKeyPair const& groupSignatureKey,
    Crypto::EncryptionKeyPair const& groupEncryptionKey);

tc::cotask<SGroupId> create(
    UserAccessor& userAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    std::vector<SPublicIdentity> const& spublicIdentities);

tc::cotask<std::vector<uint8_t>> generateAddUserToGroupBlock(
    std::vector<User> const& memberUsers,
    std::vector<PublicProvisionalUser> const& memberProvisionalUsers,
    BlockGenerator const& blockGenerator,
    Group const& group);

tc::cotask<void> updateMembers(
    UserAccessor& userAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    GroupStore const& groupStore,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd);
}
}
}
