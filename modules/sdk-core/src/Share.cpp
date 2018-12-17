#include <Tanker/Share.hpp>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Trustchain.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UserAccessor.hpp>
#include <Tanker/UserNotFound.hpp>

#include <fmt/format.h>
#include <mpark/variant.hpp>

#include <algorithm>
#include <iterator>

namespace Tanker
{
namespace Share
{
std::vector<uint8_t> makeKeyPublishToDevice(
    BlockGenerator const& blockGenerator,
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    DeviceId const& recipientDeviceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Crypto::Mac const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey = Crypto::asymEncrypt<Crypto::EncryptedSymmetricKey>(
      resourceKey, selfPrivateEncryptionKey, recipientPublicEncryptionKey);

  return blockGenerator.keyPublish(encryptedKey, resourceId, recipientDeviceId);
}

std::vector<uint8_t> makeKeyPublishToUser(
    BlockGenerator const& blockGenerator,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Crypto::Mac const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey = Crypto::sealEncrypt<Crypto::SealedSymmetricKey>(
      resourceKey, recipientPublicEncryptionKey);

  return blockGenerator.keyPublishToUser(
      encryptedKey, resourceId, recipientPublicEncryptionKey);
}

std::vector<uint8_t> makeKeyPublishToGroup(
    BlockGenerator const& blockGenerator,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Crypto::Mac const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey = Crypto::sealEncrypt<Crypto::SealedSymmetricKey>(
      resourceKey, recipientPublicEncryptionKey);

  return blockGenerator.keyPublishToGroup(
      encryptedKey, resourceId, recipientPublicEncryptionKey);
}

namespace
{
tc::cotask<ResourceKeys> getResourceKeys(
    ResourceKeyStore const& resourceKeyStore,
    gsl::span<Crypto::Mac const> resourceIds)
{
  std::vector<std::tuple<Crypto::SymmetricKey, Crypto::Mac>> resourceKeys;
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
                               std::get<Crypto::Mac>(keyResource),
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
                                std::get<Crypto::Mac>(keyResource),
                                std::get<Crypto::SymmetricKey>(keyResource)));
  return out;
}

std::vector<std::vector<uint8_t>> generateShareBlocksToDevices(
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    BlockGenerator const& blockGenerator,
    ResourceKeys const& resourceKeys,
    std::vector<Device> const& recipientDevices)
{
  std::vector<std::vector<uint8_t>> out;
  out.reserve(recipientDevices.size());
  for (auto const& keyResource : resourceKeys)
    for (auto const& recipientDevice : recipientDevices)
      out.push_back(
          makeKeyPublishToDevice(blockGenerator,
                                 selfPrivateEncryptionKey,
                                 recipientDevice.id,
                                 recipientDevice.publicEncryptionKey,
                                 std::get<Crypto::Mac>(keyResource),
                                 std::get<Crypto::SymmetricKey>(keyResource)));
  return out;
}
}

tc::cotask<KeyRecipients> generateRecipientList(
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    std::vector<UserId> const& userIds,
    std::vector<GroupId> const& groupIds)
{
  auto const userResult = TC_AWAIT(userAccessor.pull(userIds));

  auto const groupResult = TC_AWAIT(groupAccessor.pull(groupIds));

  if (!groupResult.notFound.empty() || !userResult.notFound.empty())
  {
    throw Error::RecipientNotFound(
        fmt::format(
            fmt("unknown users: [{:s}], groups [{:s}]"),
            fmt::join(
                begin(userResult.notFound), end(userResult.notFound), ", "),
            fmt::join(
                begin(groupResult.notFound), end(groupResult.notFound), ", ")),
        userResult.notFound,
        groupResult.notFound);
  }

  KeyRecipients out;
  for (auto const& user : userResult.found)
  {
    // if the user doesn't have a user key (device creation < 3), share to each
    // device
    if (user.userKey)
      out.recipientUserKeys.push_back(*user.userKey);
    else
      out.recipientDevices.insert(
          out.recipientDevices.end(), user.devices.begin(), user.devices.end());
  }

  std::transform(begin(groupResult.found),
                 end(groupResult.found),
                 std::back_inserter(out.recipientGroupKeys),
                 [](auto const& group) { return group.publicEncryptionKey; });

  TC_RETURN(out);
}

std::vector<std::vector<uint8_t>> generateShareBlocks(
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    BlockGenerator const& blockGenerator,
    ResourceKeys const& resourceKeys,
    KeyRecipients const& keyRecipients)
{
  auto keyPublishesToUsers = generateShareBlocksToUsers(
      blockGenerator, resourceKeys, keyRecipients.recipientUserKeys);
  auto keyPublishesToGroups = generateShareBlocksToGroups(
      blockGenerator, resourceKeys, keyRecipients.recipientGroupKeys);
  auto keyPublishesToDevices =
      generateShareBlocksToDevices(selfPrivateEncryptionKey,
                                   blockGenerator,
                                   resourceKeys,
                                   keyRecipients.recipientDevices);

  auto out = keyPublishesToUsers;
  out.insert(
      out.end(), keyPublishesToGroups.begin(), keyPublishesToGroups.end());
  out.insert(
      out.end(), keyPublishesToDevices.begin(), keyPublishesToDevices.end());
  return out;
}

tc::cotask<void> share(
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    ResourceKeys const& resourceKeys,
    std::vector<UserId> const& userIds,
    std::vector<GroupId> const& groupIds)
{
  auto const keyRecipients = TC_AWAIT(
      generateRecipientList(userAccessor, groupAccessor, userIds, groupIds));

  auto const ks = generateShareBlocks(
      selfPrivateEncryptionKey, blockGenerator, resourceKeys, keyRecipients);

  if (!ks.empty())
    TC_AWAIT(client.pushKeys(ks));
}

tc::cotask<void> share(
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    ResourceKeyStore const& resourceKeyStore,
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    std::vector<Crypto::Mac> const& resourceIds,
    std::vector<UserId> const& userIds,
    std::vector<GroupId> const& groupIds)
{
  auto const resourceKeys =
      TC_AWAIT(getResourceKeys(resourceKeyStore, resourceIds));

  TC_AWAIT(share(selfPrivateEncryptionKey,
                 userAccessor,
                 groupAccessor,
                 blockGenerator,
                 client,
                 resourceKeys,
                 userIds,
                 groupIds));
}
}
}
