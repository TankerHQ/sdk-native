#include <Tanker/Share.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/UserAccessor.hpp>
#include <Tanker/UserNotFound.hpp>

#include <fmt/format.h>
#include <mpark/variant.hpp>

#include <algorithm>
#include <iterator>

using Tanker::Trustchain::GroupId;
using Tanker::Trustchain::ResourceId;
using Tanker::Trustchain::UserId;

namespace Tanker
{
namespace Share
{
namespace
{
std::vector<uint8_t> makeKeyPublishToProvisionalUser(
    BlockGenerator const& blockGenerator,
    PublicProvisionalUser const& recipientProvisionalUser,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKeyOnce = Crypto::sealEncrypt(
      resourceKey, recipientProvisionalUser.appEncryptionPublicKey);
  auto const encryptedKeyTwice =
      Crypto::sealEncrypt<Crypto::TwoTimesSealedSymmetricKey>(
          encryptedKeyOnce, recipientProvisionalUser.tankerEncryptionPublicKey);

  return blockGenerator.keyPublishToProvisionalUser(
      recipientProvisionalUser.appSignaturePublicKey,
      recipientProvisionalUser.tankerSignaturePublicKey,
      resourceId,
      encryptedKeyTwice);
}

std::vector<uint8_t> makeKeyPublishToGroup(
    BlockGenerator const& blockGenerator,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey = Crypto::sealEncrypt<Crypto::SealedSymmetricKey>(
      resourceKey, recipientPublicEncryptionKey);

  return blockGenerator.keyPublishToGroup(
      encryptedKey, resourceId, recipientPublicEncryptionKey);
}

struct PartitionedIdentities
{
  std::vector<UserId> userIds;
  std::vector<Identity::PublicProvisionalIdentity> publicProvisionalIdentities;
};

PartitionedIdentities partitionIdentities(
    std::vector<Identity::PublicIdentity> const& identities)
{
  PartitionedIdentities out;
  for (auto const& identity : identities)
  {
    if (auto const i =
            mpark::get_if<Identity::PublicPermanentIdentity>(&identity))
      out.userIds.push_back(i->userId);
    else if (auto const i =
                 mpark::get_if<Identity::PublicProvisionalIdentity>(&identity))
      out.publicProvisionalIdentities.push_back(*i);
    else
      throw std::runtime_error(
          "assertion failure: unknown variant value in identity");
  }
  return out;
}

tc::cotask<ResourceKeys> getResourceKeys(
    ResourceKeyStore const& resourceKeyStore,
    gsl::span<ResourceId const> resourceIds)
{
  ResourceKeys resourceKeys;
  resourceKeys.reserve(resourceIds.size());
  for (auto const& resourceId : resourceIds)
    resourceKeys.emplace_back(std::make_tuple(
        TC_AWAIT(resourceKeyStore.getKey(resourceId)), resourceId));
  TC_RETURN(resourceKeys);
}

std::vector<std::vector<uint8_t>> generateShareBlocksToUsers(
    BlockGenerator const& blockGenerator,
    ResourceKeys const& resourceKeys,
    std::vector<Crypto::PublicEncryptionKey> const& recipientUserKeys)
{
  std::vector<std::vector<uint8_t>> out;
  out.reserve(recipientUserKeys.size());
  for (auto const& keyResource : resourceKeys)
    for (auto const& recipientKey : recipientUserKeys)
      out.push_back(
          makeKeyPublishToUser(blockGenerator,
                               recipientKey,
                               std::get<Trustchain::ResourceId>(keyResource),
                               std::get<Crypto::SymmetricKey>(keyResource)));
  return out;
}

std::vector<std::vector<uint8_t>> generateShareBlocksToProvisionalUsers(
    BlockGenerator const& blockGenerator,
    ResourceKeys const& resourceKeys,
    std::vector<PublicProvisionalUser> const& recipientProvisionalUserKeys)
{
  std::vector<std::vector<uint8_t>> out;
  out.reserve(recipientProvisionalUserKeys.size());
  for (auto const& keyResource : resourceKeys)
    for (auto const& recipientKey : recipientProvisionalUserKeys)
      out.push_back(makeKeyPublishToProvisionalUser(
          blockGenerator,
          recipientKey,
          std::get<ResourceId>(keyResource),
          std::get<Crypto::SymmetricKey>(keyResource)));
  return out;
}

std::vector<std::vector<uint8_t>> generateShareBlocksToGroups(
    BlockGenerator const& blockGenerator,
    ResourceKeys const& resourceKeys,
    std::vector<Crypto::PublicEncryptionKey> const& recipientUserKeys)
{
  std::vector<std::vector<uint8_t>> out;
  out.reserve(recipientUserKeys.size());
  for (auto const& keyResource : resourceKeys)
    for (auto const& recipientKey : recipientUserKeys)
      out.push_back(
          makeKeyPublishToGroup(blockGenerator,
                                recipientKey,
                                std::get<Trustchain::ResourceId>(keyResource),
                                std::get<Crypto::SymmetricKey>(keyResource)));
  return out;
}
}

std::vector<uint8_t> makeKeyPublishToUser(
    BlockGenerator const& blockGenerator,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey = Crypto::sealEncrypt<Crypto::SealedSymmetricKey>(
      resourceKey, recipientPublicEncryptionKey);

  return blockGenerator.keyPublishToUser(
      encryptedKey, resourceId, recipientPublicEncryptionKey);
}

tc::cotask<KeyRecipients> generateRecipientList(
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    Client& client,
    std::vector<Identity::PublicIdentity> const& publicIdentities,
    std::vector<GroupId> const& groupIds)
{
  auto const partitionedIdentities = partitionIdentities(publicIdentities);

  auto const userResult =
      TC_AWAIT(userAccessor.pull(partitionedIdentities.userIds));

  std::vector<Email> provisionalUserEmails;
  for (auto const& provisionalIdentity :
       partitionedIdentities.publicProvisionalIdentities)
  {
    if (provisionalIdentity.target != Identity::TargetType::Email)
      throw Error::formatEx("unsupported target type: {}",
                            static_cast<int>(provisionalIdentity.target));
    provisionalUserEmails.push_back(Email{provisionalIdentity.value});
  }
  auto const tankerPublicProvisionalIdentityResult =
      TC_AWAIT(client.getPublicProvisionalIdentities(provisionalUserEmails));

  if (partitionedIdentities.publicProvisionalIdentities.size() !=
      tankerPublicProvisionalIdentityResult.size())
    throw Error::InternalError(
        "getPublicProvisionalIdentities returned a list of different size");

  auto const groupResult = TC_AWAIT(groupAccessor.pull(groupIds));

  if (!groupResult.notFound.empty() || !userResult.notFound.empty())
  {
    throw Error::RecipientNotFoundInternal(userResult.notFound,
                                           groupResult.notFound);
  }

  KeyRecipients out;
  for (auto const& user : userResult.found)
  {
    if (!user.userKey)
      throw std::runtime_error(
          "sharing to users without user key is not supported anymore");
    out.recipientUserKeys.push_back(*user.userKey);
  }

  std::transform(partitionedIdentities.publicProvisionalIdentities.begin(),
                 partitionedIdentities.publicProvisionalIdentities.end(),
                 tankerPublicProvisionalIdentityResult.begin(),
                 std::back_inserter(out.recipientProvisionalUserKeys),
                 [](auto const& appPublicProvisionalIdentity,
                    auto const& tankerPublicProvisionalIdentity) {
                   return PublicProvisionalUser{
                       appPublicProvisionalIdentity.appSignaturePublicKey,
                       appPublicProvisionalIdentity.appEncryptionPublicKey,
                       tankerPublicProvisionalIdentity.first,
                       tankerPublicProvisionalIdentity.second,
                   };
                 });

  for (auto const& group : groupResult.found)
    out.recipientGroupKeys.push_back(group.publicEncryptionKey);

  TC_RETURN(out);
}

std::vector<std::vector<uint8_t>> generateShareBlocks(
    BlockGenerator const& blockGenerator,
    ResourceKeys const& resourceKeys,
    KeyRecipients const& keyRecipients)
{
  auto keyPublishesToUsers = generateShareBlocksToUsers(
      blockGenerator, resourceKeys, keyRecipients.recipientUserKeys);
  auto keyPublishesToProvisionalUsers = generateShareBlocksToProvisionalUsers(
      blockGenerator, resourceKeys, keyRecipients.recipientProvisionalUserKeys);
  auto keyPublishesToGroups = generateShareBlocksToGroups(
      blockGenerator, resourceKeys, keyRecipients.recipientGroupKeys);

  auto out = keyPublishesToUsers;
  out.insert(out.end(),
             keyPublishesToProvisionalUsers.begin(),
             keyPublishesToProvisionalUsers.end());
  out.insert(
      out.end(), keyPublishesToGroups.begin(), keyPublishesToGroups.end());
  return out;
}

tc::cotask<void> share(
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    ResourceKeys const& resourceKeys,
    std::vector<Identity::PublicIdentity> const& publicIdentities,
    std::vector<GroupId> const& groupIds)
{
  auto const keyRecipients = TC_AWAIT(generateRecipientList(
      userAccessor, groupAccessor, client, publicIdentities, groupIds));

  auto const ks =
      generateShareBlocks(blockGenerator, resourceKeys, keyRecipients);

  if (!ks.empty())
    TC_AWAIT(client.pushKeys(ks));
}

tc::cotask<void> share(
    ResourceKeyStore const& resourceKeyStore,
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    std::vector<Trustchain::ResourceId> const& resourceIds,
    std::vector<Identity::PublicIdentity> const& publicIdentities,
    std::vector<GroupId> const& groupIds)
{
  auto const resourceKeys =
      TC_AWAIT(getResourceKeys(resourceKeyStore, resourceIds));

  TC_AWAIT(share(userAccessor,
                 groupAccessor,
                 blockGenerator,
                 client,
                 resourceKeys,
                 publicIdentities,
                 groupIds));
}
}
}
