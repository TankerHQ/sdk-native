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

tc::cotask<SGroupId> create(
    Users::IUserAccessor& userAccessor,
    IRequester& requester,
    std::vector<SPublicIdentity> const& spublicIdentities,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
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
  TC_RETURN(mgs::base64::encode(groupSignatureKeyPair.publicKey));
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
    std::vector<Trustchain::UserId> const& userIDsToRemove,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    std::vector<Identity::PublicIdentity> const& publicIdentitiesToRemove)
{
  boost::container::flat_set<Trustchain::UserId> usersToAddSet;
  for (auto const& user : usersToAdd)
    usersToAddSet.insert(user.id());

  // Note that removing and adding the same user is allowed here (no-op)
  boost::container::flat_set<Trustchain::UserId> userIdsToRemove;
  for (auto const& user : userIDsToRemove)
    userIdsToRemove.insert(user);

  std::vector<RawUserGroupMember2> users;
  for (auto const& user : existingUsers)
  {
    if (userIdsToRemove.erase(user.userId()))
      continue;
    usersToAddSet.erase(user.userId());
    users.push_back({user.userId(), user.userPublicKey()});
  }
  if (!userIdsToRemove.empty())
  {
    auto const notFoundIdentities = mapIdentitiesToStrings(
        userIDsToRemove, spublicIdentitiesToRemove, publicIdentitiesToRemove);
    throw formatEx(Errc::InvalidArgument,
                   "unknown users to remove: {:s}",
                   fmt::join(notFoundIdentities, ", "));
  }

  // Silently skip duplicate adds (not an error since GroupAddition allows them)
  for (auto const& user : usersToAdd)
    if (usersToAddSet.contains(user.id()))
      users.push_back({user.id(), *user.userKey()});

  return users;
}

static std::vector<RawUserGroupProvisionalMember3> applyGroupProvisionalDiff(
    std::vector<UserGroupProvisionalMember3> const& existingUsers,
    std::vector<ProvisionalUsers::PublicUser> const& usersToAdd,
    std::vector<Identity::PublicProvisionalIdentity> const& identitiesToRemove)
{
  boost::container::flat_set<Crypto::PublicSignatureKey> usersToAddSet;
  for (auto&& user : usersToAdd)
    usersToAddSet.insert(user.appSignaturePublicKey);

  // Note that removing and adding the same user is allowed here (no-op)
  boost::container::flat_set<Crypto::PublicSignatureKey> provisionalsToRemove;
  for (auto&& user : identitiesToRemove)
    provisionalsToRemove.insert(user.appSignaturePublicKey);

  std::vector<RawUserGroupProvisionalMember3> provisionalUsers;
  for (auto&& user : existingUsers)
  {
    if (provisionalsToRemove.erase(user.appPublicSignatureKey()))
      continue;
    usersToAddSet.erase(user.appPublicSignatureKey());
    provisionalUsers.push_back({user.appPublicSignatureKey(),
                                user.tankerPublicSignatureKey(),
                                user.appPublicEncryptionKey(),
                                user.tankerPublicEncryptionKey()});
  }
  if (!provisionalsToRemove.empty())
  {
    throw formatEx(Errc::InvalidArgument,
                   "{} provisional users to remove were not found",
                   provisionalsToRemove.size());
  }

  // Silently skip duplicate adds (not an error since GroupAddition allows them)
  for (auto&& user : usersToAdd)
    if (usersToAddSet.contains(user.appSignaturePublicKey))
      provisionalUsers.push_back({user.appSignaturePublicKey,
                                  user.tankerSignaturePublicKey,
                                  user.appEncryptionPublicKey,
                                  user.tankerEncryptionPublicKey});

  return provisionalUsers;
}

tc::cotask<void> updateMembers(
    Users::IUserAccessor& userAccessor,
    IRequester& requester,
    IAccessor& groupAccessor,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd,
    std::vector<SPublicIdentity> const& spublicIdentitiesToRemove,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
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
    auto provisionalUsers =
        applyGroupProvisionalDiff(groups.found[0].provisionalMembers,
                                  newMembers.provisionalUsers,
                                  membersToRemove.publicProvisionalIdentities);

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
  }
}
}
