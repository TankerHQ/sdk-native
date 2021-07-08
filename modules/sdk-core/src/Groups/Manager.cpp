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

tc::cotask<MembersToRemove> fetchMembersToRemove(
    Users::IUserAccessor& userAccessor,
    std::vector<SPublicIdentity> spublicIdentities)
{
  spublicIdentities = removeDuplicates(std::move(spublicIdentities));
  auto const publicIdentities = extractPublicIdentities(spublicIdentities);
  auto members = partitionIdentities(publicIdentities);

  MembersToRemove ret;
  ret.users = std::move(members.userIds);

  auto const memberProvisionalUsers = TC_AWAIT(
      userAccessor.pullProvisional(members.publicProvisionalIdentities));

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
  auto const group = TC_AWAIT(groupAccessor.getInternalGroup(groupId));

  std::optional<Trustchain::Actions::UserGroupAddition> groupAddEntry;
  std::optional<Trustchain::Actions::UserGroupRemoval> groupRemoveEntry;

  if (!spublicIdentitiesToAdd.empty())
  {
    auto const members =
        TC_AWAIT(fetchFutureMembers(userAccessor, spublicIdentitiesToAdd));

    groupAddEntry = makeUserGroupAdditionAction(members.users,
                                                members.provisionalUsers,
                                                group,
                                                trustchainId,
                                                deviceId,
                                                privateSignatureKey);
  }

  if (!spublicIdentitiesToRemove.empty())
  {
    auto const membersToRemove =
        TC_AWAIT(fetchMembersToRemove(userAccessor, spublicIdentitiesToRemove));

    groupRemoveEntry =
        makeUserGroupRemovalAction(membersToRemove.users,
                                   membersToRemove.provisionalUsers,
                                   group,
                                   trustchainId,
                                   deviceId,
                                   privateSignatureKey);
  }

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
