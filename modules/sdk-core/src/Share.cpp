#include <Tanker/Share.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Users/IRequester.hpp>

#include <Tanker/Actions/Deduplicate.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/IdentityUtils.hpp>
#include <Tanker/ResourceKeys/Store.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/IUserAccessor.hpp>
#include <Tanker/Utils.hpp>

#include <boost/variant2/variant.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <algorithm>

static constexpr auto ShareLimit = 100;

using namespace Tanker::Trustchain;

namespace Tanker
{
namespace Share
{
namespace
{
std::vector<Trustchain::Actions::KeyPublishToUser> generateShareBlocksToUsers(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys::KeysResult const& resourceKeys,
    std::vector<Crypto::PublicEncryptionKey> const& recipientUserKeys)
{
  std::vector<Trustchain::Actions::KeyPublishToUser> out;
  out.reserve(resourceKeys.size() * recipientUserKeys.size());
  for (auto const& keyResource : resourceKeys)
    for (auto const& recipientKey : recipientUserKeys)
      out.push_back(makeKeyPublishToUser(trustchainId,
                                         deviceId,
                                         signatureKey,
                                         recipientKey,
                                         keyResource.resourceId,
                                         keyResource.key));
  return out;
}

std::vector<Trustchain::Actions::KeyPublishToProvisionalUser>
generateShareBlocksToProvisionalUsers(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys::KeysResult const& resourceKeys,
    std::vector<ProvisionalUsers::PublicUser> const&
        recipientProvisionalUserKeys)
{
  std::vector<Trustchain::Actions::KeyPublishToProvisionalUser> out;
  out.reserve(resourceKeys.size() * recipientProvisionalUserKeys.size());
  for (auto const& keyResource : resourceKeys)
    for (auto const& recipientKey : recipientProvisionalUserKeys)
      out.push_back(makeKeyPublishToProvisionalUser(trustchainId,
                                                    deviceId,
                                                    signatureKey,
                                                    recipientKey,
                                                    keyResource.resourceId,
                                                    keyResource.key));
  return out;
}

std::vector<Trustchain::Actions::KeyPublishToUserGroup>
generateShareBlocksToGroups(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys::KeysResult const& resourceKeys,
    std::vector<Crypto::PublicEncryptionKey> const& recipientUserKeys)
{
  std::vector<Trustchain::Actions::KeyPublishToUserGroup> out;
  out.reserve(resourceKeys.size() * recipientUserKeys.size());
  for (auto const& keyResource : resourceKeys)
    for (auto const& recipientKey : recipientUserKeys)
      out.push_back(makeKeyPublishToGroup(trustchainId,
                                          deviceId,
                                          signatureKey,
                                          recipientKey,
                                          keyResource.resourceId,
                                          keyResource.key));
  return out;
}

void handleNotFound(
    std::vector<SPublicIdentity> const& spublicIdentities,
    std::vector<Identity::PublicIdentity> const& publicIdentities,
    std::vector<Trustchain::UserId> const& usersNotFound,
    std::vector<SGroupId> const& sgroupIds,
    std::vector<GroupId> const& groupIds,
    std::vector<Trustchain::GroupId> const& groupsNotFound)
{
  if (!groupsNotFound.empty() || !usersNotFound.empty())
  {
    auto const clearPublicIdentities = mapIdentitiesToStrings(
        usersNotFound, spublicIdentities, publicIdentities);
    throw Errors::formatEx(
        Errors::Errc::InvalidArgument,
        FMT_STRING("unknown public identities: [{:s}], unknown groups: [{:s}]"),
        fmt::join(clearPublicIdentities, ", "),
        fmt::join(groupsNotFound, ", "));
  }
}

KeyRecipients toKeyRecipients(
    std::vector<Users::User> const& users,
    std::vector<ProvisionalUsers::PublicUser> const& publicProvisionalUsers,
    std::vector<Crypto::PublicEncryptionKey> const& groupEncryptionKeys)
{
  KeyRecipients out;
  for (auto const& user : users)
  {
    if (!user.userKey())
    {
      throw Errors::AssertionError(
          "sharing to users without user key is not supported anymore");
    }
    out.recipientUserKeys.push_back(*user.userKey());
  }

  out.recipientProvisionalUserKeys = publicProvisionalUsers;
  out.recipientGroupKeys = groupEncryptionKeys;

  return out;
}
}

Trustchain::Actions::KeyPublishToUser makeKeyPublishToUser(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey =
      Crypto::sealEncrypt(resourceKey, recipientPublicEncryptionKey);

  return Users::createKeyPublishToUserAction(trustchainId,
                                             deviceId,
                                             signatureKey,
                                             encryptedKey,
                                             resourceId,
                                             recipientPublicEncryptionKey);
}

Trustchain::Actions::KeyPublishToUserGroup makeKeyPublishToGroup(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey = Crypto::sealEncrypt<Crypto::SealedSymmetricKey>(
      resourceKey, recipientPublicEncryptionKey);

  return Groups::createKeyPublishToGroupAction(encryptedKey,
                                               resourceId,
                                               recipientPublicEncryptionKey,
                                               trustchainId,
                                               deviceId,
                                               signatureKey);
}

Trustchain::Actions::KeyPublishToProvisionalUser
makeKeyPublishToProvisionalUser(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ProvisionalUsers::PublicUser const& recipientProvisionalUser,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKeyOnce = Crypto::sealEncrypt(
      resourceKey, recipientProvisionalUser.appEncryptionPublicKey());
  auto const encryptedKeyTwice = Crypto::sealEncrypt(
      encryptedKeyOnce, recipientProvisionalUser.tankerEncryptionPublicKey());

  return Users::createKeyPublishToProvisionalUserAction(
      trustchainId,
      deviceId,
      signatureKey,
      recipientProvisionalUser.appSignaturePublicKey(),
      recipientProvisionalUser.tankerSignaturePublicKey(),
      resourceId,
      encryptedKeyTwice);
}

tc::cotask<KeyRecipients> generateRecipientList(
    Trustchain::TrustchainId const& trustchainId,
    Users::IUserAccessor& userAccessor,
    Groups::IAccessor& groupAccessor,
    std::vector<SPublicIdentity> spublicIdentities,
    std::vector<SGroupId> sgroupIds)
{
  spublicIdentities |= Actions::deduplicate;
  sgroupIds |= Actions::deduplicate;

  auto const groupIds = sgroupIds |
                        ranges::views::transform([](auto&& sgroupId) {
                          return base64DecodeArgument<Trustchain::GroupId>(
                              sgroupId.string(), "group id");
                        }) |
                        ranges::to<std::vector>;
  auto const publicIdentities =
      spublicIdentities | ranges::views::transform(extractPublicIdentity) |
      ranges::to<std::vector>;

  ensureIdentitiesInTrustchain(publicIdentities, trustchainId);

  auto const partitionedIdentities = partitionIdentities(publicIdentities);

  auto const userResult = TC_AWAIT(userAccessor.pull(
      partitionedIdentities.userIds, Users::IRequester::IsLight::Yes));

  auto const groupResult =
      TC_AWAIT(groupAccessor.getPublicEncryptionKeys(groupIds));

  handleNotFound(spublicIdentities,
                 publicIdentities,
                 userResult.notFound,
                 sgroupIds,
                 groupIds,
                 groupResult.notFound);

  auto const provisionalUsers = TC_AWAIT(userAccessor.pullProvisional(
      partitionedIdentities.publicProvisionalIdentities));

  TC_RETURN(
      toKeyRecipients(userResult.found, provisionalUsers, groupResult.found));
}

ShareActions generateShareBlocks(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys::KeysResult const& resourceKeys,
    KeyRecipients const& keyRecipients)
{
  auto keyPublishesToUsers =
      generateShareBlocksToUsers(trustchainId,
                                 deviceId,
                                 signatureKey,
                                 resourceKeys,
                                 keyRecipients.recipientUserKeys);
  auto keyPublishesToProvisionalUsers = generateShareBlocksToProvisionalUsers(
      trustchainId,
      deviceId,
      signatureKey,
      resourceKeys,
      keyRecipients.recipientProvisionalUserKeys);
  auto keyPublishesToGroups =
      generateShareBlocksToGroups(trustchainId,
                                  deviceId,
                                  signatureKey,
                                  resourceKeys,
                                  keyRecipients.recipientGroupKeys);

  return {std::move(keyPublishesToUsers),
          std::move(keyPublishesToGroups),
          std::move(keyPublishesToProvisionalUsers)};
}

tc::cotask<void> share(Users::IUserAccessor& userAccessor,
                       Groups::IAccessor& groupAccessor,
                       Trustchain::TrustchainId const& trustchainId,
                       Trustchain::DeviceId const& deviceId,
                       Crypto::PrivateSignatureKey const& signatureKey,
                       Users::IRequester& requester,
                       ResourceKeys::KeysResult const& resourceKeys,
                       std::vector<SPublicIdentity> const& publicIdentities,
                       std::vector<SGroupId> const& groupIds)
{
  if (resourceKeys.empty())
    throw Errors::AssertionError("no keys to share");

  if (publicIdentities.size() + groupIds.size() > ShareLimit)
    throw formatEx(Errors::Errc::InvalidArgument,
                   "cannot share with more than {} recipients at once",
                   ShareLimit);

  auto const keyRecipients = TC_AWAIT(generateRecipientList(
      trustchainId, userAccessor, groupAccessor, publicIdentities, groupIds));

  auto const actions = generateShareBlocks(
      trustchainId, deviceId, signatureKey, resourceKeys, keyRecipients);

  TC_AWAIT(requester.postResourceKeys(actions));
}

}
}
