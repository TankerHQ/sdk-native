#pragma once

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Groups/Group.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/PublicProvisionalUser.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>

#include <tconcurrent/coroutine.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace Tanker::Users
{
class IUserAccessor;
struct User;
}

namespace Tanker::Groups::Manager
{
static constexpr size_t MAX_GROUP_SIZE = 1000;

struct MembersToAdd
{
  std::vector<Users::User> users;
  std::vector<PublicProvisionalUser> provisionalUsers;
};

tc::cotask<MembersToAdd> fetchFutureMembers(
    Users::IUserAccessor& userAccessor,
    std::vector<SPublicIdentity> spublicIdentities);

std::vector<uint8_t> generateCreateGroupBlock(
    std::vector<Users::User> const& memberUsers,
    std::vector<PublicProvisionalUser> const& memberProvisionalUsers,
    BlockGenerator const& blockGenerator,
    Crypto::SignatureKeyPair const& groupSignatureKey,
    Crypto::EncryptionKeyPair const& groupEncryptionKey);

tc::cotask<SGroupId> create(
    Users::IUserAccessor& userAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    std::vector<SPublicIdentity> const& spublicIdentities);

std::vector<uint8_t> generateAddUserToGroupBlock(
    std::vector<Users::User> const& memberUsers,
    std::vector<PublicProvisionalUser> const& memberProvisionalUsers,
    BlockGenerator const& blockGenerator,
    InternalGroup const& group);

tc::cotask<void> updateMembers(
    Users::IUserAccessor& userAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    IAccessor& groupAccessor,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd);
}
