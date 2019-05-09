#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/GroupNotFound.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
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
namespace
{

// this function can exist because for the moment, a public identity can only
// contain a user id
std::vector<UserId> publicIdentitiesToUserIds(
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  return convertList(spublicIdentities, [](auto&& spublicIdentity) {
    return mpark::get<Identity::PublicPermanentIdentity>(
               Identity::extract<Identity::PublicIdentity>(
                   spublicIdentity.string()))
        .userId;
  });
}
}

tc::cotask<std::vector<User>> getMemberKeys(
    UserAccessor& userAccessor, std::vector<UserId> const& memberUserIds)
{
  auto const result = TC_AWAIT(userAccessor.pull(memberUserIds));
  if (!result.notFound.empty())
    throw Error::UserNotFoundInternal(result.notFound);

  TC_RETURN(result.found);
}

namespace
{
UserGroupCreation2::UserGroupMembers generateGroupKeysForUsers2(
    Crypto::PrivateEncryptionKey const& groupPrivateEncryptionKey,
    std::vector<User> const& users)
{
  UserGroupCreation2::UserGroupMembers keysForUsers;
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
}

tc::cotask<std::vector<uint8_t>> generateCreateGroupBlock(
    std::vector<User> const& memberUsers,
    BlockGenerator const& blockGenerator,
    Crypto::SignatureKeyPair const& groupSignatureKey,
    Crypto::EncryptionKeyPair const& groupEncryptionKey)
{
  if (memberUsers.size() == 0)
    throw Error::InvalidGroupSize("Cannot create an empty group");
  else if (memberUsers.size() > MAX_GROUP_SIZE)
    throw Error::formatEx<Error::InvalidGroupSize>(
        fmt("Cannot create group with {:d} members, max is {:d}"),
        memberUsers.size(),
        MAX_GROUP_SIZE);

  TC_RETURN(blockGenerator.userGroupCreation2(
      groupSignatureKey,
      groupEncryptionKey.publicKey,
      generateGroupKeysForUsers2(groupEncryptionKey.privateKey, memberUsers),
      {}));
}

tc::cotask<SGroupId> create(UserAccessor& userAccessor,
                            BlockGenerator const& blockGenerator,
                            Client& client,
                            std::vector<SPublicIdentity> spublicIdentities)
{
  spublicIdentities = removeDuplicates(std::move(spublicIdentities));
  auto members = publicIdentitiesToUserIds(spublicIdentities);

  try
  {
    auto memberUsers = TC_AWAIT(getMemberKeys(userAccessor, members));

    auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
    auto groupSignatureKey = Crypto::makeSignatureKeyPair();

    auto const groupBlock = TC_AWAIT(generateCreateGroupBlock(
        memberUsers, blockGenerator, groupSignatureKey, groupEncryptionKey));
    TC_AWAIT(client.pushBlock(groupBlock));

    TC_RETURN(cppcodec::base64_rfc4648::encode(groupSignatureKey.publicKey));
  }
  catch (Error::UserNotFoundInternal const& e)
  {
    auto const notFoundIdentities =
        mapIdsToStrings(e.userIds(), spublicIdentities, members);
    throw Error::UserNotFound(fmt::format(fmt("Unknown users: {:s}"),
                                          fmt::join(notFoundIdentities.begin(),
                                                    notFoundIdentities.end(),
                                                    ", ")),
                              notFoundIdentities);
  }
  throw std::runtime_error("unreachable code");
}

tc::cotask<std::vector<uint8_t>> generateAddUserToGroupBlock(
    std::vector<User> const& memberUsers,
    BlockGenerator const& blockGenerator,
    Group const& group)
{
  if (memberUsers.size() == 0)
    throw Error::InvalidGroupSize("Adding 0 members to a group is an error");
  else if (memberUsers.size() > MAX_GROUP_SIZE)
    throw Error::formatEx<Error::InvalidGroupSize>(
        fmt("Cannot add {:d} members to a group, max is {:d}"),
        memberUsers.size(),
        MAX_GROUP_SIZE);

  UserGroupAddition::v1::SealedPrivateEncryptionKeysForUsers sealedEncKeys;
  for (auto const& user : memberUsers)
  {
    if (!user.userKey)
      throw std::runtime_error(
          "Cannot create group for users without a user key");

    sealedEncKeys.emplace_back(
        *user.userKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            group.encryptionKeyPair.privateKey, *user.userKey));
  }

  TC_RETURN(blockGenerator.userGroupAddition(
      group.signatureKeyPair, group.lastBlockHash, sealedEncKeys));
}

tc::cotask<void> updateMembers(
    UserAccessor& userAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    GroupStore const& groupStore,
    GroupId const& groupId,
    std::vector<SPublicIdentity> spublicIdentitiesToAdd)
{
  spublicIdentitiesToAdd = removeDuplicates(std::move(spublicIdentitiesToAdd));
  auto usersToAdd = publicIdentitiesToUserIds(spublicIdentitiesToAdd);

  try
  {
    auto const memberUsers = TC_AWAIT(getMemberKeys(userAccessor, usersToAdd));
    auto const group = TC_AWAIT(groupStore.findFullById(groupId));
    if (!group)
      throw Error::GroupNotFound(
          "Cannot update members of a group we aren't part of");

    auto const groupBlock = TC_AWAIT(
        generateAddUserToGroupBlock(memberUsers, blockGenerator, *group));
    TC_AWAIT(client.pushBlock(groupBlock));
  }
  catch (Error::UserNotFoundInternal const& e)
  {
    auto const notFoundIdentities =
        mapIdsToStrings(e.userIds(), spublicIdentitiesToAdd, usersToAdd);
    throw Error::UserNotFound(fmt::format(fmt("Unknown users: {:s}"),
                                          fmt::join(notFoundIdentities.begin(),
                                                    notFoundIdentities.end(),
                                                    ", ")),
                              notFoundIdentities);
  }
}
}
}
}
