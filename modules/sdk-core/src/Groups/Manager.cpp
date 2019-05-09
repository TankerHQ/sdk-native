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

tc::cotask<std::vector<Crypto::PublicEncryptionKey>> getMemberKeys(
    UserAccessor& userAccessor, std::vector<UserId> const& memberUserIds)
{
  auto const result = TC_AWAIT(userAccessor.pull(memberUserIds));
  if (!result.notFound.empty())
  {
    throw Error::UserNotFoundInternal(result.notFound);
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

  Trustchain::Actions::UserGroupCreation1::SealedPrivateEncryptionKeysForUsers
      sealedEncKeys;
  for (auto const& userKey : memberUserKeys)
  {
    sealedEncKeys.emplace_back(
        userKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            groupEncryptionKey.privateKey, userKey));
  }

  TC_RETURN(blockGenerator.userGroupCreation(
      groupSignatureKey, groupEncryptionKey.publicKey, sealedEncKeys));
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
    auto memberUserKeys = TC_AWAIT(getMemberKeys(userAccessor, members));

    auto groupEncryptionKey = Crypto::makeEncryptionKeyPair();
    auto groupSignatureKey = Crypto::makeSignatureKeyPair();

    auto const groupBlock = TC_AWAIT(generateCreateGroupBlock(
        memberUserKeys, blockGenerator, groupSignatureKey, groupEncryptionKey));
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

  UserGroupAddition::v1::SealedPrivateEncryptionKeysForUsers sealedEncKeys;
  for (auto const& userKey : memberUserKeys)
  {
    sealedEncKeys.emplace_back(
        userKey,
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            group.encryptionKeyPair.privateKey, userKey));
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
    auto const memberUserKeys =
        TC_AWAIT(getMemberKeys(userAccessor, usersToAdd));
    auto const group = TC_AWAIT(groupStore.findFullById(groupId));
    if (!group)
      throw Error::GroupNotFound(
          "Cannot update members of a group we aren't part of");

    auto const groupBlock = TC_AWAIT(
        generateAddUserToGroupBlock(memberUserKeys, blockGenerator, *group));
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
