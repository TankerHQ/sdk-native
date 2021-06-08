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

namespace
{
template <typename T>
void checkAddedAndRemoved(
    boost::container::flat_set<T> const& usersToAddSet,
    boost::container::flat_set<T> const& userIdsToRemoveSet,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    std::vector<Identity::PublicIdentity> const& publicIdentitiesToRemove)
{
  std::vector<T> usersBothAddedAndRemoved;
  std::set_intersection(usersToAddSet.begin(),
                        usersToAddSet.end(),
                        userIdsToRemoveSet.begin(),
                        userIdsToRemoveSet.end(),
                        std::back_inserter(usersBothAddedAndRemoved));

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
}

tc::cotask<std::pair<std::vector<RawUserGroupMember2>,
                     std::vector<UserGroupProvisionalMember3>>>
upgradeGroupMembers(
    Users::IUserAccessor& userAccessor,
    ProvisionalUsers::IAccessor::ProvisionalUserClaims claimedUserIds,
    std::vector<UserGroupProvisionalMember3> const& provisionalMembers)
{
  std::vector<Trustchain::UserId> memberUserIds;
  std::vector<UserGroupProvisionalMember3> outProvisionalMembers;
  for (auto const& provisionalMember : provisionalMembers)
  {
    if (auto const& it =
            claimedUserIds.find({provisionalMember.appPublicSignatureKey(),
                                 provisionalMember.tankerPublicSignatureKey()});
        it != claimedUserIds.end())
      memberUserIds.push_back(it->second);
    else
      outProvisionalMembers.push_back(provisionalMember);
  }

  auto memberUsers = TC_AWAIT(
      userAccessor.pull(memberUserIds, Users::IRequester::IsLight::Yes));

  if (!memberUsers.notFound.empty())
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "found claiming users but couldn't pull them: {}",
                           fmt::join(memberUsers.notFound, ", "));

  std::vector<RawUserGroupMember2> outMembers;
  for (auto const& user : memberUsers.found)
    outMembers.push_back({user.id(), user.userKey().value()});

  TC_RETURN((std::pair<std::vector<RawUserGroupMember2>,
                       std::vector<UserGroupProvisionalMember3>>{
      std::move(outMembers), std::move(outProvisionalMembers)}));
}

std::vector<RawUserGroupMember2> applyGroupUserDiff(
    std::vector<RawUserGroupMember2> const& existingUsers,
    std::vector<Users::User> const& usersToAdd,
    std::vector<Trustchain::UserId> const& userIdsToRemove,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    std::vector<Identity::PublicIdentity> const& publicIdentitiesToRemove)
{
  boost::container::flat_set<Trustchain::UserId> userIdsToAddSet;
  for (auto const& user : usersToAdd)
    userIdsToAddSet.insert(user.id());
  boost::container::flat_set<Trustchain::UserId> userIdsToRemoveSet(
      userIdsToRemove.begin(), userIdsToRemove.end());

  checkAddedAndRemoved(userIdsToAddSet,
                       userIdsToRemoveSet,
                       spublicIdentitiesToRemove,
                       publicIdentitiesToRemove);

  std::vector<RawUserGroupMember2> finalUsers;
  for (auto const& user : existingUsers)
  {
    if (userIdsToRemoveSet.erase(user.userId))
      continue;
    userIdsToAddSet.erase(user.userId);
    finalUsers.push_back({user.userId, user.userPublicKey});
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
    if (userIdsToAddSet.erase(user.id()))
    {
      finalUsers.push_back({user.id(), *user.userKey()});
    }
  }

  return finalUsers;
}

std::vector<RawUserGroupProvisionalMember3> applyGroupProvisionalDiff(
    std::vector<UserGroupProvisionalMember3> const& existingUsers,
    std::vector<ProvisionalUsers::PublicUser> const& usersToAdd,
    std::vector<ProvisionalUsers::PublicUser> const& usersToRemove,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    std::vector<Identity::PublicIdentity> const& publicIdentitiesToRemove)
{
  boost::container::flat_set<ProvisionalUsers::PublicUser> usersToAddSet(
      usersToAdd.begin(), usersToAdd.end());
  boost::container::flat_set<ProvisionalUsers::PublicUser>
      provisionalsToRemoveSet(usersToRemove.begin(), usersToRemove.end());

  checkAddedAndRemoved(usersToAddSet,
                       provisionalsToRemoveSet,
                       spublicIdentitiesToRemove,
                       publicIdentitiesToRemove);

  std::vector<RawUserGroupProvisionalMember3> provisionalUsers;
  for (auto const& user : existingUsers)
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
        mapIdentitiesToStrings(provisionalsToRemove,
                               spublicIdentitiesToRemove,
                               publicIdentitiesToRemove);
    throw formatEx(Errc::InvalidArgument,
                   "provisional identities to remove not found: {:s}",
                   fmt::join(problematicIdentities, ", "));
  }

  // Silently skip duplicate adds (not an error since GroupAddition allows them)
  for (auto const& user : usersToAdd)
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

tc::cotask<void> addGroupMembers(
    Users::IUserAccessor& userAccessor,
    IRequester& requester,
    IAccessor& groupAccessor,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const newMembers =
      TC_AWAIT(fetchFutureMembers(userAccessor, spublicIdentitiesToAdd));

  auto const group = TC_AWAIT(groupAccessor.getInternalGroup(groupId));

  auto const groupEntry =
      makeUserGroupAdditionAction(newMembers.users,
                                  newMembers.provisionalUsers,
                                  group,
                                  trustchainId,
                                  deviceId,
                                  privateSignatureKey);
  TC_AWAIT(requester.updateGroup(groupEntry));
}

void checkRemoveClaimedIdentities(
    ProvisionalUsers::IAccessor::ProvisionalUserClaims const& claimedUserIds,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemoveDedup,
    std::vector<Identity::PublicIdentity> const& publicIdentitiesToRemove,
    std::vector<ProvisionalUsers::PublicUser> const& provisionalUsersToRemove)
{
  std::vector<ProvisionalUsers::PublicUser> claimedIdentitiesToRemove;
  for (auto const& toRemove : provisionalUsersToRemove)
    if (claimedUserIds.find({toRemove.appSignaturePublicKey,
                             toRemove.tankerSignaturePublicKey}) !=
        claimedUserIds.end())
      claimedIdentitiesToRemove.push_back(toRemove);

  if (!claimedIdentitiesToRemove.empty())
  {
    auto const problematicIdentities =
        mapIdentitiesToStrings(claimedIdentitiesToRemove,
                               spublicIdentitiesToRemoveDedup,
                               publicIdentitiesToRemove);
    throw formatEx(Errc::IdentityAlreadyAttached,
                   "the following identities are already claimed: {:s}",
                   fmt::join(problematicIdentities, ", "));
  }
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>> addAndRemoveMembers(
    Users::IUserAccessor& userAccessor,
    ProvisionalUsers::IAccessor& provisionalUserAccessor,
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

  auto const groupAndMembers =
      TC_AWAIT(groupAccessor.getInternalGroupAndMembers(groupId));

  auto const spublicIdentitiesToRemoveDedup =
      removeDuplicates(spublicIdentitiesToRemove);
  auto const publicIdentitiesToRemove =
      extractPublicIdentities(spublicIdentitiesToRemoveDedup);
  auto const membersToRemove = partitionIdentities(publicIdentitiesToRemove);

  auto const provisionalUsersToRemove = TC_AWAIT(userAccessor.pullProvisional(
      membersToRemove.publicProvisionalIdentities));

  std::vector<ProvisionalUsers::ProvisionalUserId> provisionalUsersToQuery;
  for (auto const& provisionalMember : groupAndMembers.provisionalMembers)
    provisionalUsersToQuery.push_back(
        {provisionalMember.appPublicSignatureKey(),
         provisionalMember.tankerPublicSignatureKey()});
  for (auto const& toRemove : provisionalUsersToRemove)
    provisionalUsersToQuery.push_back(
        {toRemove.appSignaturePublicKey, toRemove.tankerSignaturePublicKey});

  auto const claimedUserIds = TC_AWAIT(
      provisionalUserAccessor.pullClaimingUserIds(provisionalUsersToQuery));

  checkRemoveClaimedIdentities(claimedUserIds,
                               spublicIdentitiesToRemoveDedup,
                               publicIdentitiesToRemove,
                               provisionalUsersToRemove);

  auto [groupMembersWithUpgradedMembers, newProvisionalUsers] =
      TC_AWAIT(upgradeGroupMembers(
          userAccessor, claimedUserIds, groupAndMembers.provisionalMembers));
  for (auto const& member : groupAndMembers.members)
    groupMembersWithUpgradedMembers.push_back(
        {member.userId(), member.userPublicKey()});

  auto users = applyGroupUserDiff(groupMembersWithUpgradedMembers,
                                  newMembers.users,
                                  membersToRemove.userIds,
                                  spublicIdentitiesToRemoveDedup,
                                  publicIdentitiesToRemove);

  auto provisionalUsers =
      applyGroupProvisionalDiff(newProvisionalUsers,
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
                                                    groupAndMembers.group,
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

tc::cotask<std::optional<Crypto::EncryptionKeyPair>> updateMembers(
    Users::IUserAccessor& userAccessor,
    ProvisionalUsers::IAccessor& provisionalUserAccessor,
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
  if (spublicIdentitiesToRemove.empty())
  {
    TC_AWAIT(addGroupMembers(userAccessor,
                             requester,
                             groupAccessor,
                             groupId,
                             spublicIdentitiesToAdd,
                             trustchainId,
                             deviceId,
                             privateSignatureKey));
    TC_RETURN(std::nullopt);
  }
  else
  {
    TC_RETURN(TC_AWAIT(addAndRemoveMembers(userAccessor,
                                           provisionalUserAccessor,
                                           requester,
                                           groupAccessor,
                                           groupId,
                                           spublicIdentitiesToAdd,
                                           spublicIdentitiesToRemove,
                                           trustchainId,
                                           deviceId,
                                           privateSignatureKey,
                                           userId)));
  }
}
}
