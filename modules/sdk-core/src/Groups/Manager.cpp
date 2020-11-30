#include <Tanker/Groups/Manager.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/IdentityUtils.hpp>
#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
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

  auto const memberUsers = TC_AWAIT(userAccessor.pull(members.userIds));
  if (!memberUsers.notFound.empty())
  {
    auto const notFoundIdentities = mapIdsToStrings(
        memberUsers.notFound, spublicIdentities, members.userIds);
    throw formatEx(Errc::InvalidArgument,
                   "unknown users: {:s}",
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
        FMT_STRING("cannot create a group with {:d} members, max is {:d}"),
        groupSize,
        MAX_GROUP_SIZE);
  }

  auto groupMembers = generateGroupKeysForUsers2(
      groupEncryptionKeyPair.privateKey, memberUsers);
  auto groupProvisionalMembers = generateGroupKeysForProvisionalUsers2(
      groupEncryptionKeyPair.privateKey, memberProvisionalUsers);
  return createUserGroupCreationV2Action(groupSignatureKeyPair,
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
        FMT_STRING("cannot add {:d} members to a group, max is {:d}"),
        groupSize,
        MAX_GROUP_SIZE);
  }

  auto members = generateGroupKeysForUsers2(group.encryptionKeyPair.privateKey,
                                            memberUsers);
  if (group.version == GroupBlocksVersion::V3)
  {
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
  else
  {
    auto provisionalMembers = generateGroupKeysForProvisionalUsers2(
        group.encryptionKeyPair.privateKey, memberProvisionalUsers);
    return createUserGroupAdditionV2Action(group.signatureKeyPair,
                                           group.lastBlockHash,
                                           members,
                                           provisionalMembers,
                                           trustchainId,
                                           deviceId,
                                           privateSignatureKey);
  }
}

tc::cotask<void> updateMembers(
    Users::IUserAccessor& userAccessor,
    IRequester& requester,
    IAccessor& groupAccessor,
    Trustchain::GroupId const& groupId,
    std::vector<SPublicIdentity> const& spublicIdentitiesToAdd,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  auto const members =
      TC_AWAIT(fetchFutureMembers(userAccessor, spublicIdentitiesToAdd));

  auto const groups = TC_AWAIT(groupAccessor.getInternalGroups({groupId}));
  if (groups.found.empty())
    throw formatEx(Errc::InvalidArgument, "no such group: {:s}", groupId);

  auto const groupEntry = makeUserGroupAdditionAction(members.users,
                                                      members.provisionalUsers,
                                                      groups.found[0],
                                                      trustchainId,
                                                      deviceId,
                                                      privateSignatureKey);
  TC_AWAIT(requester.updateGroup(groupEntry));
}
}
