#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/GroupNotFound.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/IdentityUtils.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/UserNotFound.hpp>
#include <Tanker/Utils.hpp>

#include <cppcodec/base64_rfc4648.hpp>

using Tanker::Trustchain::GroupId;
using Tanker::Trustchain::UserId;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
namespace Groups
{
namespace Manager
{
tc::cotask<MembersToAdd> fetchFutureMembers(
    UserAccessor& userAccessor, std::vector<SPublicIdentity> spublicIdentities)
{
  spublicIdentities = removeDuplicates(std::move(spublicIdentities));
  auto const publicIdentities = extractPublicIdentities(spublicIdentities);
  auto const members = partitionIdentities(publicIdentities);

  auto const memberUsers = TC_AWAIT(userAccessor.pull(members.userIds));
  if (!memberUsers.notFound.empty())
  {
    auto const notFoundIdentities = mapIdsToStrings(
        memberUsers.notFound, spublicIdentities, members.userIds);
    throw Error::UserNotFound(fmt::format(fmt("Unknown users: {:s}"),
                                          fmt::join(notFoundIdentities.begin(),
                                                    notFoundIdentities.end(),
                                                    ", ")),
                              notFoundIdentities);
  }

  auto const memberProvisionalUsers = TC_AWAIT(
      userAccessor.pullProvisional(members.publicProvisionalIdentities));

  TC_RETURN((MembersToAdd{
      memberUsers.found,
      memberProvisionalUsers,
  }));
}

namespace
{
UserGroupCreation::v2::Members generateGroupKeysForUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<User> const& users)
{
  UserGroupCreation::v2::Members keysForUsers;
  for (auto const& user : users)
  {
    if (!user.userKey)
      throw std::runtime_error(
          "Cannot create group for users without a user key");

    keysForUsers.emplace_back(
        user.id,
        *user.userKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            groupPrivateEncryptionKey, *user.userKey));
  }
  return keysForUsers;
}

UserGroupCreation::v2::ProvisionalMembers
generateGroupKeysForProvisionalUsers(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<PublicProvisionalUser> const& users)
{
  UserGroupCreation::v2::ProvisionalMembers keysForUsers;
  for (auto const& user : users)
  {
    auto const encryptedKeyOnce = Crypto::sealEncrypt(
        groupPrivateEncryptionKey, user.appEncryptionPublicKey);
    auto const encryptedKeyTwice =
        Crypto::sealEncrypt<Crypto::TwoTimesSealedPrivateEncryptionKey>(
            encryptedKeyOnce, user.tankerEncryptionPublicKey);

    keysForUsers.emplace_back(user.appSignaturePublicKey,
                              user.tankerSignaturePublicKey,
                              encryptedKeyTwice);
  }
  return keysForUsers;
}
}

std::vector<uint8_t> generateCreateGroupBlock(
    std::vector<User> const& memberUsers,
    std::vector<PublicProvisionalUser> const& memberProvisionalUsers,
    BlockGenerator const& blockGenerator,
    Crypto::SignatureKeyPair const& groupSignatureKey,
    Crypto::EncryptionKeyPair const& groupEncryptionKey)
{
  auto const groupSize = memberUsers.size() + memberProvisionalUsers.size();
  if (groupSize == 0)
    throw Error::InvalidGroupSize("Cannot create an empty group");
  else if (groupSize > MAX_GROUP_SIZE)
    throw Error::formatEx<Error::InvalidGroupSize>(
        fmt("Cannot create group with {:d} members, max is {:d}"),
        groupSize,
        MAX_GROUP_SIZE);

  return blockGenerator.userGroupCreation2(
      groupSignatureKey,
      groupEncryptionKey.publicKey,
      generateGroupKeysForUsers2(groupEncryptionKey.privateKey, memberUsers),
      generateGroupKeysForProvisionalUsers(groupEncryptionKey.privateKey,
                                           memberProvisionalUsers));
}

tc::cotask<SGroupId> create(
    UserAccessor& userAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  auto const members =
      TC_AWAIT(fetchFutureMembers(userAccessor, spublicIdentities));

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  auto const groupBlock = generateCreateGroupBlock(members.users,
                                                   members.provisionalUsers,
                                                   blockGenerator,
                                                   groupSignatureKey,
                                                   groupEncryptionKey);
  TC_AWAIT(client.pushBlock(groupBlock));

  TC_RETURN(cppcodec::base64_rfc4648::encode(groupSignatureKey.publicKey));
}

std::vector<uint8_t> generateAddUserToGroupBlock(
    std::vector<User> const& memberUsers,
    std::vector<PublicProvisionalUser> const& memberProvisionalUsers,
    BlockGenerator const& blockGenerator,
    Group const& group)
{
  auto const groupSize = memberUsers.size() + memberProvisionalUsers.size();
  if (groupSize == 0)
    throw Error::InvalidGroupSize("Adding 0 members to a group is an error");
  else if (groupSize > MAX_GROUP_SIZE)
    throw Error::formatEx<Error::InvalidGroupSize>(
        fmt("Cannot add {:d} members to a group, max is {:d}"),
        groupSize,
        MAX_GROUP_SIZE);

  return blockGenerator.userGroupAddition2(
      group.signatureKeyPair,
      group.lastBlockHash,
      generateGroupKeysForUsers2(group.encryptionKeyPair.privateKey,
                                 memberUsers),
      generateGroupKeysForProvisionalUsers(group.encryptionKeyPair.privateKey,
                                           memberProvisionalUsers));
}

tc::cotask<void> updateMembers(
    UserAccessor& userAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    GroupStore const& groupStore,
    GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd)
{
  auto const members =
      TC_AWAIT(fetchFutureMembers(userAccessor, spublicIdentitiesToAdd));

  auto const group = TC_AWAIT(groupStore.findFullById(groupId));
  if (!group)
    throw Error::GroupNotFound(
        "Cannot update members of a group we aren't part of");

  auto const groupBlock = generateAddUserToGroupBlock(
      members.users, members.provisionalUsers, blockGenerator, *group);
  TC_AWAIT(client.pushBlock(groupBlock));
}
}
}
}
