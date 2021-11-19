#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Actions/Deduplicate.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Users/IUserAccessor.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Utils.hpp>

#include <mgs/base64.hpp>

#include <range/v3/action/sort.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/set_algorithm.hpp>
#include <range/v3/view/transform.hpp>

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker::Groups::Manager
{
namespace
{
ProcessedIdentities processIdentities(
    Trustchain::TrustchainId const& trustchainId,
    std::vector<SPublicIdentity> identities)
{
  ProcessedIdentities ret;
  ret.spublicIdentities = std::move(identities) | Actions::deduplicate;
  ret.publicIdentities = ret.spublicIdentities |
                         ranges::views::transform(extractPublicIdentity) |
                         ranges::to<std::vector>;
  ensureIdentitiesInTrustchain(ret.publicIdentities, trustchainId);
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

  ret.provisionalUsers =
      memberProvisionalUsers |
      ranges::views::transform(&ProvisionalUsers::PublicUser::id) |
      ranges::to<std::vector>;

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
      processIdentities(trustchainId, std::move(spublicIdentities));

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
  usersToAdd |= ranges::actions::sort;
  usersToRemove |= ranges::actions::sort;

  auto const usersBothAddedAndRemoved =
      ranges::views::set_intersection(usersToAdd, usersToRemove) |
      ranges::to<std::vector>;

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

auto createGroupEntries(Users::IUserAccessor& userAccessor,
                        Trustchain::TrustchainId const& trustchainId,
                        InternalGroup const& group,
                        Trustchain::DeviceId const& deviceId,
                        Crypto::PrivateSignatureKey const& privateSignatureKey,
                        std::vector<SPublicIdentity> spublicIdentitiesToAdd,
                        std::vector<SPublicIdentity> spublicIdentitiesToRemove)
{
  MembersToAdd membersToAdd;
  MembersToRemove membersToRemove;

  std::optional<Trustchain::Actions::UserGroupAddition> groupAddEntry;
  std::optional<Trustchain::Actions::UserGroupRemoval> groupRemoveEntry;

  auto const processedIdentitiesToAdd =
      processIdentities(trustchainId, std::move(spublicIdentitiesToAdd));
  auto const processedIdentitiesToRemove =
      processIdentities(trustchainId, std::move(spublicIdentitiesToRemove));

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

  checkAddedAndRemoved(membersToAdd.users |
                           ranges::views::transform(&Users::User::id) |
                           ranges::to<std::vector>,
                       membersToRemove.users,
                       processedIdentitiesToAdd);

  checkAddedAndRemoved(
      membersToAdd.provisionalUsers |
          ranges::views::transform(&ProvisionalUsers::PublicUser::id) |
          ranges::to<std::vector>,
      membersToRemove.provisionalUsers,
      processedIdentitiesToAdd);
  return std::make_pair(std::move(groupAddEntry), std::move(groupRemoveEntry));
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
                   "no members to add or remove in updateMembers");

  auto const group = TC_AWAIT(groupAccessor.getInternalGroup(groupId));
  auto const [groupAddEntry, groupRemoveEntry] =
      createGroupEntries(userAccessor,
                         trustchainId,
                         group,
                         deviceId,
                         privateSignatureKey,
                         std::move(spublicIdentitiesToAdd),
                         std::move(spublicIdentitiesToRemove));

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
