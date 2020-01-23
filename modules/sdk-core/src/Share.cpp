#include <Tanker/Share.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/IdentityUtils.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/IUserAccessor.hpp>
#include <Tanker/Utils.hpp>

#include <boost/variant2/variant.hpp>

#include <algorithm>
#include <iterator>

using namespace Tanker::Trustchain;

namespace Tanker
{
namespace Share
{
namespace
{
std::vector<uint8_t> makeKeyPublishToProvisionalUser(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    PublicProvisionalUser const& recipientProvisionalUser,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKeyOnce = Crypto::sealEncrypt(
      resourceKey, recipientProvisionalUser.appEncryptionPublicKey);
  auto const encryptedKeyTwice = Crypto::sealEncrypt(
      encryptedKeyOnce, recipientProvisionalUser.tankerEncryptionPublicKey);

  return Serialization::serialize(Users::createKeyPublishToProvisionalUserEntry(
      trustchainId,
      deviceId,
      signatureKey,
      recipientProvisionalUser.appSignaturePublicKey,
      recipientProvisionalUser.tankerSignaturePublicKey,
      resourceId,
      encryptedKeyTwice));
}

std::vector<uint8_t> makeKeyPublishToGroup(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey = Crypto::sealEncrypt<Crypto::SealedSymmetricKey>(
      resourceKey, recipientPublicEncryptionKey);

  return Serialization::serialize(
      Groups::createKeyPublishToGroupEntry(encryptedKey,
                                           resourceId,
                                           recipientPublicEncryptionKey,
                                           trustchainId,
                                           deviceId,
                                           signatureKey));
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
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys const& resourceKeys,
    std::vector<Crypto::PublicEncryptionKey> const& recipientUserKeys)
{
  std::vector<std::vector<uint8_t>> out;
  out.reserve(recipientUserKeys.size());
  for (auto const& keyResource : resourceKeys)
  {
    for (auto const& recipientKey : recipientUserKeys)
    {
      out.push_back(
          makeKeyPublishToUser(trustchainId,
                               deviceId,
                               signatureKey,
                               recipientKey,
                               std::get<Trustchain::ResourceId>(keyResource),
                               std::get<Crypto::SymmetricKey>(keyResource)));
    }
  }
  return out;
}

std::vector<std::vector<uint8_t>> generateShareBlocksToProvisionalUsers(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys const& resourceKeys,
    std::vector<PublicProvisionalUser> const& recipientProvisionalUserKeys)
{
  std::vector<std::vector<uint8_t>> out;
  out.reserve(recipientProvisionalUserKeys.size());
  for (auto const& keyResource : resourceKeys)
  {
    for (auto const& recipientKey : recipientProvisionalUserKeys)
    {
      out.push_back(makeKeyPublishToProvisionalUser(
          trustchainId,
          deviceId,
          signatureKey,
          recipientKey,
          std::get<ResourceId>(keyResource),
          std::get<Crypto::SymmetricKey>(keyResource)));
    }
  }
  return out;
}

std::vector<std::vector<uint8_t>> generateShareBlocksToGroups(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys const& resourceKeys,
    std::vector<Crypto::PublicEncryptionKey> const& recipientUserKeys)
{
  std::vector<std::vector<uint8_t>> out;
  out.reserve(recipientUserKeys.size());
  for (auto const& keyResource : resourceKeys)
  {
    for (auto const& recipientKey : recipientUserKeys)
    {
      out.push_back(
          makeKeyPublishToGroup(trustchainId,
                                deviceId,
                                signatureKey,
                                recipientKey,
                                std::get<Trustchain::ResourceId>(keyResource),
                                std::get<Crypto::SymmetricKey>(keyResource)));
    }
  }
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
    auto const clearPublicIdentities = mapIdsToStrings(
        usersNotFound,
        spublicIdentities,
        publicIdentities,
        [](auto const& identity) {
          auto const permanentIdentity =
              boost::variant2::get_if<Identity::PublicPermanentIdentity>(
                  &identity);
          return permanentIdentity ?
                     std::make_optional(permanentIdentity->userId) :
                     std::nullopt;
        });
    auto const clearGids = mapIdsToStrings(groupsNotFound, sgroupIds, groupIds);
    throw Errors::formatEx(
        Errors::Errc::InvalidArgument,
        TFMT("unknown public identities: [{:s}], unknown groups: [{:s}]"),
        fmt::join(clearPublicIdentities, ", "),
        fmt::join(clearGids, ", "));
  }
}

KeyRecipients toKeyRecipients(
    std::vector<Users::User> const& users,
    std::vector<PublicProvisionalUser> const& publicProvisionalUsers,
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

std::vector<uint8_t> makeKeyPublishToUser(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey)
{
  auto const encryptedKey =
      Crypto::sealEncrypt(resourceKey, recipientPublicEncryptionKey);

  return Serialization::serialize(
      Users::createKeyPublishToUserEntry(trustchainId,
                                         deviceId,
                                         signatureKey,
                                         encryptedKey,
                                         resourceId,
                                         recipientPublicEncryptionKey));
}

tc::cotask<KeyRecipients> generateRecipientList(
    Users::IUserAccessor& userAccessor,
    Groups::IAccessor& groupAccessor,
    std::vector<SPublicIdentity> const& aspublicIdentities,
    std::vector<SGroupId> const& asgroupIds)
{
  auto const spublicIdentities = removeDuplicates(aspublicIdentities);
  auto const sgroupIds = removeDuplicates(asgroupIds);

  auto const publicIdentities = extractPublicIdentities(spublicIdentities);
  auto const groupIds = convertToGroupIds(sgroupIds);

  auto const partitionedIdentities = partitionIdentities(publicIdentities);

  auto const userResult =
      TC_AWAIT(userAccessor.pull(partitionedIdentities.userIds));

  auto const provisionalUsers = TC_AWAIT(userAccessor.pullProvisional(
      partitionedIdentities.publicProvisionalIdentities));

  auto const groupResult =
      TC_AWAIT(groupAccessor.getPublicEncryptionKeys(groupIds));

  handleNotFound(spublicIdentities,
                 publicIdentities,
                 userResult.notFound,
                 sgroupIds,
                 groupIds,
                 groupResult.notFound);

  TC_RETURN(
      toKeyRecipients(userResult.found, provisionalUsers, groupResult.found));
}

std::vector<std::vector<uint8_t>> generateShareBlocks(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys const& resourceKeys,
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

  auto out = keyPublishesToUsers;
  out.insert(out.end(),
             keyPublishesToProvisionalUsers.begin(),
             keyPublishesToProvisionalUsers.end());
  out.insert(
      out.end(), keyPublishesToGroups.begin(), keyPublishesToGroups.end());
  return out;
}

tc::cotask<void> share(Users::IUserAccessor& userAccessor,
                       Groups::IAccessor& groupAccessor,
                       Trustchain::TrustchainId const& trustchainId,
                       Trustchain::DeviceId const& deviceId,
                       Crypto::PrivateSignatureKey const& signatureKey,
                       Client& client,
                       ResourceKeys const& resourceKeys,
                       std::vector<SPublicIdentity> const& publicIdentities,
                       std::vector<SGroupId> const& groupIds)
{
  auto const keyRecipients = TC_AWAIT(generateRecipientList(
      userAccessor, groupAccessor, publicIdentities, groupIds));

  auto const ks = generateShareBlocks(
      trustchainId, deviceId, signatureKey, resourceKeys, keyRecipients);

  if (!ks.empty())
    TC_AWAIT(client.pushKeys(ks));
}

tc::cotask<void> share(ResourceKeyStore const& resourceKeyStore,
                       Users::IUserAccessor& userAccessor,
                       Groups::IAccessor& groupAccessor,
                       Trustchain::TrustchainId const& trustchainId,
                       Trustchain::DeviceId const& deviceId,
                       Crypto::PrivateSignatureKey const& signatureKey,
                       Client& client,
                       std::vector<Trustchain::ResourceId> const& resourceIds,
                       std::vector<SPublicIdentity> const& publicIdentities,
                       std::vector<SGroupId> const& groupIds)
{
  auto const resourceKeys =
      TC_AWAIT(getResourceKeys(resourceKeyStore, resourceIds));

  TC_AWAIT(share(userAccessor,
                 groupAccessor,
                 trustchainId,
                 deviceId,
                 signatureKey,
                 client,
                 resourceKeys,
                 publicIdentities,
                 groupIds));
}
}
}
