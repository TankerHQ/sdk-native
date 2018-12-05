#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/GroupNotFound.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/UserNotFound.hpp>

namespace Tanker
{
namespace Groups
{
namespace Manager
{

tc::cotask<std::vector<Crypto::PublicEncryptionKey>> getMemberKeys(
    UserAccessor& userAccessor, std::vector<UserId> const& memberUserIds)
{
  auto const result = TC_AWAIT(userAccessor.pull(memberUserIds));
  if (!result.notFound.empty())
  {
    throw Error::UserNotFound(
        fmt::format(
            fmt("unknown users: '{:s}'"),
            fmt::join(begin(result.notFound), end(result.notFound), ", ")),
        result.notFound);
  }

  std::vector<Crypto::PublicEncryptionKey> out;
  out.reserve(result.found.size());
  std::transform(result.found.begin(),
                 result.found.end(),
                 std::back_inserter(out),
                 [](auto const& user) {
                   if (!user.userKey)
                     throw std::runtime_error(
                         "Cannot create group for users without a user key");

                   return *user.userKey;
                 });

  TC_RETURN(out);
}

tc::cotask<std::vector<uint8_t>> generateCreateGroupBlock(
    std::vector<Crypto::PublicEncryptionKey> const& memberUserKeys,
    BlockGenerator const& blockGenerator,
    Crypto::SignatureKeyPair const& groupSignatureKey,
    Crypto::EncryptionKeyPair const& groupEncryptionKey)
{
  if (memberUserKeys.size() == 0)
    throw Error::InvalidGroupSize("Cannot create an empty group");
  else if (memberUserKeys.size() > MAX_GROUP_SIZE)
    throw Error::formatEx<Error::InvalidGroupSize>(
        fmt("Cannot create group with {:d} members, max is {:d}"),
        memberUserKeys.size(),
        MAX_GROUP_SIZE);

  UserGroupCreation::GroupEncryptedKeys sealedEncKeys;
  for (auto const& userKey : memberUserKeys)
    sealedEncKeys.push_back(GroupEncryptedKey{
        userKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            groupEncryptionKey.privateKey, userKey)});

  TC_RETURN(blockGenerator.userGroupCreation(
      groupSignatureKey, groupEncryptionKey.publicKey, sealedEncKeys));
}

tc::cotask<SGroupId> create(UserAccessor& userAccessor,
                            BlockGenerator const& blockGenerator,
                            Client& client,
                            std::vector<UserId> const& members)
{
  auto memberUserKeys = TC_AWAIT(getMemberKeys(userAccessor, members));

  auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto groupSignatureKey = Crypto::makeSignatureKeyPair();

  auto const groupBlock = TC_AWAIT(generateCreateGroupBlock(
      memberUserKeys, blockGenerator, groupSignatureKey, groupEncryptionKey));
  TC_AWAIT(client.pushBlock(groupBlock));

  TC_RETURN(Tanker::base64::encode(groupSignatureKey.publicKey));
}

tc::cotask<std::vector<uint8_t>> generateAddUserToGroupBlock(
    std::vector<Crypto::PublicEncryptionKey> const& memberUserKeys,
    BlockGenerator const& blockGenerator,
    Group const& group)
{
  if (memberUserKeys.size() == 0)
    throw Error::InvalidGroupSize("Adding 0 members to a group is an error");
  else if (memberUserKeys.size() > MAX_GROUP_SIZE)
    throw Error::formatEx<Error::InvalidGroupSize>(
        fmt("Cannot add {:d} members to a group, max is {:d}"),
        memberUserKeys.size(),
        MAX_GROUP_SIZE);

  UserGroupAddition::GroupEncryptedKeys sealedEncKeys;
  for (auto const& userKey : memberUserKeys)
    sealedEncKeys.push_back(GroupEncryptedKey{
        userKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            group.encryptionKeyPair.privateKey, userKey)});

  TC_RETURN(blockGenerator.userGroupAddition(
      group.signatureKeyPair, group.lastBlockHash, sealedEncKeys));
}

tc::cotask<void> updateMembers(UserAccessor& userAccessor,
                               BlockGenerator const& blockGenerator,
                               Client& client,
                               GroupStore const& groupStore,
                               GroupId const& groupId,
                               std::vector<UserId> const& usersToAdd)
{
  auto const memberUserKeys = TC_AWAIT(getMemberKeys(userAccessor, usersToAdd));
  auto const group = TC_AWAIT(groupStore.findFullById(groupId));
  if (!group)
    throw Error::GroupNotFound(
        "Cannot update members of a group we aren't part of");

  auto const groupBlock = TC_AWAIT(
      generateAddUserToGroupBlock(memberUserKeys, blockGenerator, *group));
  TC_AWAIT(client.pushBlock(groupBlock));
}
}
}
}
