#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Users/IUserAccessor.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Utils.hpp>

#include <mgs/base64.hpp>

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker::Groups::Manager
{
namespace
{
ProcessedIdentities processIdentities(std::vector<SPublicIdentity> identities)
{
  ProcessedIdentities ret;
  ret.spublicIdentities = removeDuplicates(std::move(identities));
  ret.publicIdentities = extractPublicIdentities(ret.spublicIdentities);
  ret.partitionedIdentities = partitionIdentities(ret.publicIdentities);
  return ret;
}
}

tc::cotask<MembersToAdd> fetchFutureMembers(
    Users::IUserAccessor& userAccessor, ProcessedIdentities const& identities)
{
  auto const memberUsers =
      TC_AWAIT(userAccessor.pull(identities.partitionedIdentities.userIds,
                                 Users::IRequester::IsLight::Yes));
  if (!memberUsers.notFound.empty())
  {
    auto const notFoundIdentities =
        mapIdentitiesToStrings(memberUsers.notFound,
                               identities.spublicIdentities,
                               identities.publicIdentities);
    throw formatEx(Errc::InvalidArgument,
                   "public identities not found: {:s}",
                   fmt::join(notFoundIdentities, ", "));
  }
  auto const memberProvisionalUsers = TC_AWAIT(userAccessor.pullProvisional(
      identities.partitionedIdentities.publicProvisionalIdentities));

  TC_RETURN((MembersToAdd{
      memberUsers.found,
      memberProvisionalUsers,
  }));
}

tc::cotask<MembersToRemove> fetchMembersToRemove(
    Users::IUserAccessor& userAccessor, ProcessedIdentities const& identities)
{
  MembersToRemove ret;
  ret.users = identities.partitionedIdentities.userIds;

  auto const memberProvisionalUsers = TC_AWAIT(userAccessor.pullProvisional(
      identities.partitionedIdentities.publicProvisionalIdentities));

  for (auto const& member : memberProvisionalUsers)
    ret.provisionalUsers.push_back(
        {member.appSignaturePublicKey, member.tankerSignaturePublicKey});

  TC_RETURN(std::move(ret));
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
    std::vector<SPublicIdentity> spublicIdentities,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const processedIdentities =
      processIdentities(std::move(spublicIdentities));

  auto const members =
      TC_AWAIT(fetchFutureMembers(userAccessor, processedIdentities));

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

Trustchain::Actions::UserGroupRemoval makeUserGroupRemovalAction(
    std::vector<Trustchain::UserId> const& membersToRemove,
    std::vector<Trustchain::ProvisionalUserId> const&
        provisionalMembersToRemove,
    InternalGroup const& group,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey)
{
  return UserGroupRemoval{
      trustchainId,
      group.id,
      membersToRemove,
      provisionalMembersToRemove,
      deviceId,
      group.signatureKeyPair.privateKey,
      deviceSignatureKey,
  };
}

namespace
{
template <typename T>
void checkAddedAndRemoved(std::vector<T> usersToAdd,
                          std::vector<T> usersToRemove,
                          ProcessedIdentities const& identitiesToAdd)
{
  std::sort(usersToAdd.begin(), usersToAdd.end());
  std::sort(usersToRemove.begin(), usersToRemove.end());

  std::vector<T> usersBothAddedAndRemoved;
  std::set_intersection(usersToAdd.begin(),
                        usersToAdd.end(),
                        usersToRemove.begin(),
                        usersToRemove.end(),
                        std::back_inserter(usersBothAddedAndRemoved));

  if (!usersBothAddedAndRemoved.empty())
  {
    auto const identitiesBothAddedAndRemoved =
        mapIdentitiesToStrings(usersBothAddedAndRemoved,
                               identitiesToAdd.spublicIdentities,
                               identitiesToAdd.publicIdentities);
    throw formatEx(Errc::InvalidArgument,
                   "cannot both add and remove: {:s}",
                   fmt::join(identitiesBothAddedAndRemoved, ", "));
  }
}

std::vector<Trustchain::UserId> usersToUserIds(
    std::vector<Users::User> const& users)
{
  std::vector<Trustchain::UserId> ret;
  ret.reserve(users.size());
  for (auto const& u : users)
    ret.push_back(u.id());
  return ret;
}

std::vector<Trustchain::ProvisionalUserId> provisionalUsersToProvisionalUserIds(
    std::vector<ProvisionalUsers::PublicUser> const& users)
{
  std::vector<Trustchain::ProvisionalUserId> ret;
  ret.reserve(users.size());
  for (auto const& u : users)
    ret.push_back({u.appSignaturePublicKey, u.tankerSignaturePublicKey});
  return ret;
}
}

tc::cotask<void> updateMembers(
    Users::IUserAccessor& userAccessor,
    IRequester& requester,
    IAccessor& groupAccessor,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> spublicIdentitiesToAdd,
    std::vector<SPublicIdentity> spublicIdentitiesToRemove,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  if (spublicIdentitiesToAdd.empty() && spublicIdentitiesToRemove.empty())
    throw formatEx(Errc::InvalidArgument,
                   "no members to add or remove in updateGroupMembers");

  auto const group = TC_AWAIT(groupAccessor.getInternalGroup(groupId));

  auto const processedIdentitiesToAdd =
      processIdentities(std::move(spublicIdentitiesToAdd));
  auto const processedIdentitiesToRemove =
      processIdentities(std::move(spublicIdentitiesToRemove));

  MembersToAdd membersToAdd;
  MembersToRemove membersToRemove;

  std::optional<Trustchain::Actions::UserGroupAddition> groupAddEntry;
  std::optional<Trustchain::Actions::UserGroupRemoval> groupRemoveEntry;

  if (!processedIdentitiesToAdd.spublicIdentities.empty())
  {
    membersToAdd =
        TC_AWAIT(fetchFutureMembers(userAccessor, processedIdentitiesToAdd));

    groupAddEntry = makeUserGroupAdditionAction(membersToAdd.users,
                                                membersToAdd.provisionalUsers,
                                                group,
                                                trustchainId,
                                                deviceId,
                                                privateSignatureKey);
  }

  if (!processedIdentitiesToRemove.spublicIdentities.empty())
  {
    membersToRemove = TC_AWAIT(
        fetchMembersToRemove(userAccessor, processedIdentitiesToRemove));

    groupRemoveEntry =
        makeUserGroupRemovalAction(membersToRemove.users,
                                   membersToRemove.provisionalUsers,
                                   group,
                                   trustchainId,
                                   deviceId,
                                   privateSignatureKey);
  }

  checkAddedAndRemoved(usersToUserIds(membersToAdd.users),
                       membersToRemove.users,
                       processedIdentitiesToAdd);

  checkAddedAndRemoved(
      provisionalUsersToProvisionalUserIds(membersToAdd.provisionalUsers),
      membersToRemove.provisionalUsers,
      processedIdentitiesToAdd);

  if (groupRemoveEntry)
    TC_AWAIT(requester.softUpdateGroup(*groupRemoveEntry, groupAddEntry));
  else
  {
    if (!groupAddEntry)
      throw AssertionError("no user to add or remove from group");
    TC_AWAIT(requester.updateGroup(*groupAddEntry));
  }
}
}
