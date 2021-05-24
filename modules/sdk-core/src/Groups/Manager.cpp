#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/IdentityUtils.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Users/IUserAccessor.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Utils.hpp>

#include <boost/container/flat_set.hpp>
#include <mgs/base64.hpp>

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker::Groups::Manager
{
tc::cotask<MembersToAdd> fetchFutureMembers(
    Users::IUserAccessor& userAccessor,
    std::vector<SPublicIdentity> spublicIdentities)
{
  spublicIdentities = removeDuplicates(std::move(spublicIdentities));
  auto const publicIdentities = extractPublicIdentities(spublicIdentities);
  auto const members = partitionIdentities(publicIdentities);

  auto const memberUsers = TC_AWAIT(
      userAccessor.pull(members.userIds, Users::IRequester::IsLight::Yes));
  if (!memberUsers.notFound.empty())
  {
    auto const notFoundIdentities = mapIdentitiesToStrings(
        memberUsers.notFound, spublicIdentities, publicIdentities);
    throw formatEx(Errc::InvalidArgument,
                   "public identities not found: {:s}",
                   fmt::join(notFoundIdentities, ", "));
  }
  auto const memberProvisionalUsers = TC_AWAIT(
      userAccessor.pullProvisional(members.publicProvisionalIdentities));

  TC_RETURN((MembersToAdd{
      memberUsers.found,
      memberProvisionalUsers,
  }));
}

Trustchain::Actions::UserGroupCreation makeUserGroupCreationAction(
    std::vector<Users::User> const& memberUsers,
    std::vector<ProvisionalUsers::PublicUser> const& memberProvisionalUsers,
    Crypto::SignatureKeyPair const& groupSignatureKeyPair,
    Crypto::EncryptionKeyPair const& groupEncryptionKeyPair,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  auto const groupSize = memberUsers.size() + memberProvisionalUsers.size();
  if (groupSize == 0)
    throw formatEx(Errc::InvalidArgument, "cannot create an empty group");
  else if (groupSize > MAX_GROUP_SIZE)
  {
    throw formatEx(
        Errc::GroupTooBig,
        FMT_STRING("cannot add {:d} members at once to a group, max is {:d}"),
        groupSize,
        MAX_GROUP_SIZE);
  }

  auto groupMembers = generateGroupKeysForUsers2(
      groupEncryptionKeyPair.privateKey, memberUsers);
  auto groupProvisionalMembers = generateGroupKeysForProvisionalUsers3(
      groupEncryptionKeyPair.privateKey, memberProvisionalUsers);
  return createUserGroupCreationV3Action(groupSignatureKeyPair,
                                         groupEncryptionKeyPair.publicKey,
                                         groupMembers,
                                         groupProvisionalMembers,
                                         trustchainId,
                                         deviceId,
                                         deviceSignatureKey);
}

tc::cotask<GroupCreationResult> create(
    Users::IUserAccessor& userAccessor,
    IRequester& requester,
    std::vector<SPublicIdentity> const& spublicIdentities,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey,
    Trustchain::UserId const& userId)
{
  auto const members =
      TC_AWAIT(fetchFutureMembers(userAccessor, spublicIdentities));

  auto const groupEncryptionKeyPair = Crypto::makeEncryptionKeyPair();
  auto const groupSignatureKeyPair = Crypto::makeSignatureKeyPair();

  auto const groupEntry = makeUserGroupCreationAction(members.users,
                                                      members.provisionalUsers,
                                                      groupSignatureKeyPair,
                                                      groupEncryptionKeyPair,
                                                      trustchainId,
                                                      deviceId,
                                                      privateSignatureKey);

  TC_AWAIT(requester.createGroup(groupEntry));

  // Check if the author is in the group
  std::optional<Crypto::EncryptionKeyPair> encryptionKeyPair;
  if (std::find_if(
          members.users.begin(), members.users.end(), [&](auto const& user) {
            return user.id() == userId;
          }) != members.users.end())
  {
    encryptionKeyPair = groupEncryptionKeyPair;
  }

  auto result = GroupCreationResult{
      Trustchain::GroupId{groupSignatureKeyPair.publicKey}, encryptionKeyPair};
  TC_RETURN(result);
}

Trustchain::Actions::UserGroupAddition makeUserGroupAdditionAction(
    std::vector<Users::User> const& memberUsers,
    std::vector<ProvisionalUsers::PublicUser> const& memberProvisionalUsers,
    InternalGroup const& group,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const groupSize = memberUsers.size() + memberProvisionalUsers.size();
  if (groupSize == 0)
  {
    throw Exception(make_error_code(Errc::InvalidArgument),
                    "must add at least one member to a group");
  }
  else if (groupSize > MAX_GROUP_SIZE)
  {
    throw formatEx(
        Errc::GroupTooBig,
        FMT_STRING("cannot add {:d} members at once to a group, max is {:d}"),
        groupSize,
        MAX_GROUP_SIZE);
  }

  auto members = generateGroupKeysForUsers2(group.encryptionKeyPair.privateKey,
                                            memberUsers);
  auto provisionalMembers = generateGroupKeysForProvisionalUsers3(
      group.encryptionKeyPair.privateKey, memberProvisionalUsers);
  return createUserGroupAdditionV3Action(group.signatureKeyPair,
                                         group.lastBlockHash,
                                         members,
                                         provisionalMembers,
                                         trustchainId,
                                         deviceId,
                                         privateSignatureKey);
}

Trustchain::Actions::UserGroupUpdate makeUserGroupUpdateAction(
    Crypto::SignatureKeyPair const& newGroupSignatureKeyPair,
    Crypto::EncryptionKeyPair const& newGroupEncryptionKeyPair,
    std::vector<RawUserGroupMember2> const& memberUsers,
    std::vector<RawUserGroupProvisionalMember3> const& memberProvisionalUsers,
    InternalGroup const& group,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const groupSize = memberUsers.size() + memberProvisionalUsers.size();
  if (groupSize == 0)
  {
    throw formatEx(Errc::InvalidArgument,
                   "a group must have at least one member");
  }
  else if (groupSize > MAX_GROUP_SIZE)
  {
    throw formatEx(
        Errc::GroupTooBig,
        FMT_STRING("cannot have {:d} members in a group, max is {:d}"),
        groupSize,
        MAX_GROUP_SIZE);
  }

  auto members = generateGroupKeysForUsers2(
      newGroupEncryptionKeyPair.privateKey, memberUsers);
  auto provisionalMembers = generateGroupKeysForProvisionalUsers3(
      newGroupEncryptionKeyPair.privateKey, memberProvisionalUsers);
  return createUserGroupUpdateV1Action(group.id,
                                       group.lastBlockHash,
                                       group.lastKeyRotationBlockHash,
                                       newGroupSignatureKeyPair,
                                       newGroupEncryptionKeyPair.publicKey,
                                       group.signatureKeyPair,
                                       group.encryptionKeyPair,
                                       members,
                                       provisionalMembers,
                                       trustchainId,
                                       deviceId,
                                       privateSignatureKey);
}

static std::vector<RawUserGroupMember2> applyGroupUserDiff(
    std::vector<UserGroupMember2> const& existingUsers,
    std::vector<Users::User> const& usersToAdd,
    std::vector<Trustchain::UserId> const& userIdsToRemove,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    std::vector<Identity::PublicIdentity> const& publicIdentitiesToRemove)
{
  boost::container::flat_set<Trustchain::UserId> userIdsToRemoveSet;
  for (auto const& user : userIdsToRemove)
    userIdsToRemoveSet.insert(user);

  boost::container::flat_set<Trustchain::UserId> usersToAddSet;
  std::vector<Trustchain::UserId> usersBothAddedAndRemoved;
  for (auto const& user : usersToAdd)
  {
    if (userIdsToRemoveSet.contains(user.id()))
    {
      usersBothAddedAndRemoved.push_back(user.id());
    }
    usersToAddSet.insert(user.id());
  }

  if (!usersBothAddedAndRemoved.empty())
  {
    auto const problematicIdentities =
        mapIdentitiesToStrings(usersBothAddedAndRemoved,
                               spublicIdentitiesToRemove,
                               publicIdentitiesToRemove);
    throw formatEx(Errc::InvalidArgument,
                   "cannot both add and remove: {:s}",
                   fmt::join(problematicIdentities, ", "));
  }

  std::vector<RawUserGroupMember2> finalUsers;
  for (auto const& user : existingUsers)
  {
    if (userIdsToRemoveSet.erase(user.userId()))
      continue;
    usersToAddSet.erase(user.userId());
    finalUsers.push_back({user.userId(), user.userPublicKey()});
  }
  if (!userIdsToRemoveSet.empty())
  {
    std::vector<Trustchain::UserId> userIdsNotFound(userIdsToRemoveSet.begin(),
                                                    userIdsToRemoveSet.end());
    auto const problematicIdentities = mapIdentitiesToStrings(
        userIdsNotFound, spublicIdentitiesToRemove, publicIdentitiesToRemove);
    throw formatEx(Errc::InvalidArgument,
                   "Tried to remove users not in the group: {:s}",
                   fmt::join(problematicIdentities, ", "));
  }

  // Silently skip duplicate adds (not an error since GroupAddition allows them)
  for (auto const& user : usersToAdd)
  {
    if (usersToAddSet.erase(user.id()))
    {
      finalUsers.push_back({user.id(), *user.userKey()});
    }
  }

  return finalUsers;
}

static std::vector<RawUserGroupProvisionalMember3> applyGroupProvisionalDiff(
    std::vector<UserGroupProvisionalMember3> const& existingUsers,
    std::vector<ProvisionalUsers::PublicUser> const& usersToAdd,
    std::vector<ProvisionalUsers::PublicUser> const& usersToRemove,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    std::vector<Identity::PublicIdentity> const& publicIdentitiesToRemove)
{
  boost::container::flat_set<ProvisionalUsers::PublicUser> usersToAddSet;
  for (auto&& user : usersToAdd)
    usersToAddSet.insert(user);

  boost::container::flat_set<ProvisionalUsers::PublicUser>
      provisionalsToRemoveSet;
  std::vector<ProvisionalUsers::PublicUser> provisionalsBothAddedAndRemoved;

  for (auto&& user : usersToRemove)
  {
    if (usersToAddSet.contains(user))
    {
      provisionalsBothAddedAndRemoved.push_back(user);
    }
    provisionalsToRemoveSet.insert(user);
  }

  if (provisionalsBothAddedAndRemoved.size() != 0)
  {
    auto const problematicIdentities =
        mapProvisionalIdentitiesToStrings(provisionalsBothAddedAndRemoved,
                                          spublicIdentitiesToRemove,
                                          publicIdentitiesToRemove);
    throw formatEx(Errc::InvalidArgument,
                   "cannot both add and remove: {:s}",
                   fmt::join(problematicIdentities, ", "));
  }

  std::vector<RawUserGroupProvisionalMember3> provisionalUsers;
  for (auto&& user : existingUsers)
  {
    ProvisionalUsers::PublicUser publicUser = {
        user.appPublicSignatureKey(),
        user.appPublicEncryptionKey(),
        user.tankerPublicSignatureKey(),
        user.tankerPublicEncryptionKey()};
    if (provisionalsToRemoveSet.erase(publicUser))
      continue;
    usersToAddSet.erase(publicUser);
    provisionalUsers.push_back({user.appPublicSignatureKey(),
                                user.tankerPublicSignatureKey(),
                                user.appPublicEncryptionKey(),
                                user.tankerPublicEncryptionKey()});
  }
  if (!provisionalsToRemoveSet.empty())
  {
    std::vector<ProvisionalUsers::PublicUser> provisionalsToRemove(
        provisionalsToRemoveSet.begin(), provisionalsToRemoveSet.end());
    auto const problematicIdentities =
        mapProvisionalIdentitiesToStrings(provisionalsToRemove,
                                          spublicIdentitiesToRemove,
                                          publicIdentitiesToRemove);
    throw formatEx(Errc::InvalidArgument,
                   "provisional identities to remove not found: {:s}",
                   fmt::join(problematicIdentities, ", "));
  }

  // Silently skip duplicate adds (not an error since GroupAddition allows them)
  for (auto&& user : usersToAdd)
  {
    if (usersToAddSet.erase(user))
    {
      provisionalUsers.push_back({user.appSignaturePublicKey,
                                  user.tankerSignaturePublicKey,
                                  user.appEncryptionPublicKey,
                                  user.tankerEncryptionPublicKey});
    }
  }
  return provisionalUsers;
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>> updateMembers(
    Users::IUserAccessor& userAccessor,
    IRequester& requester,
    IAccessor& groupAccessor,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey,
    Trustchain::UserId const& userId)
{
  auto const newMembers =
      TC_AWAIT(fetchFutureMembers(userAccessor, spublicIdentitiesToAdd));

  if (spublicIdentitiesToRemove.empty())
  {
    auto const groups = TC_AWAIT(groupAccessor.getInternalGroups({groupId}));
    if (groups.found.empty())
      throw formatEx(Errc::InvalidArgument, "no such group: {:s}", groupId);

    auto const groupEntry =
        makeUserGroupAdditionAction(newMembers.users,
                                    newMembers.provisionalUsers,
                                    groups.found[0],
                                    trustchainId,
                                    deviceId,
                                    privateSignatureKey);
    TC_AWAIT(requester.updateGroup(groupEntry));
    TC_RETURN(std::nullopt);
  }
  else
  {
    auto const groups =
        TC_AWAIT(groupAccessor.getInternalGroupsAndMembers({groupId}));
    if (groups.found.empty())
      throw formatEx(Errc::InvalidArgument, "no such group: {:s}", groupId);

    auto const spublicIdentitiesToRemoveDedup =
        removeDuplicates(spublicIdentitiesToRemove);
    auto const publicIdentitiesToRemove =
        extractPublicIdentities(spublicIdentitiesToRemoveDedup);
    auto const membersToRemove = partitionIdentities(publicIdentitiesToRemove);

    auto users = applyGroupUserDiff(groups.found[0].members,
                                    newMembers.users,
                                    membersToRemove.userIds,
                                    spublicIdentitiesToRemoveDedup,
                                    publicIdentitiesToRemove);

    auto const provisionalUsersToRemove = TC_AWAIT(userAccessor.pullProvisional(
        membersToRemove.publicProvisionalIdentities));

    auto provisionalUsers =
        applyGroupProvisionalDiff(groups.found[0].provisionalMembers,
                                  newMembers.provisionalUsers,
                                  provisionalUsersToRemove,
                                  spublicIdentitiesToRemoveDedup,
                                  publicIdentitiesToRemove);

    auto const newGroupSignatureKeyPair = Crypto::makeSignatureKeyPair();
    auto const newGroupEncryptionKeyPair = Crypto::makeEncryptionKeyPair();
    auto const groupEntry = makeUserGroupUpdateAction(newGroupSignatureKeyPair,
                                                      newGroupEncryptionKeyPair,
                                                      users,
                                                      provisionalUsers,
                                                      groups.found[0].group,
                                                      trustchainId,
                                                      deviceId,
                                                      privateSignatureKey);
    TC_AWAIT(requester.updateGroup(groupEntry));

    // Check if the author is in the group
    std::optional<Crypto::EncryptionKeyPair> encryptionKeyPair;
    if (std::find_if(newMembers.users.begin(),
                     newMembers.users.end(),
                     [&](auto const& user) { return user.id() == userId; }) !=
        newMembers.users.end())
    {
      encryptionKeyPair = newGroupEncryptionKeyPair;
    }

    TC_RETURN(encryptionKeyPair);
  }
}
}
