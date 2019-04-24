#pragma once

#include <Tanker/Device.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainStore.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <tuple>
#include <vector>

namespace Tanker
{
class BlockGenerator;
class UserAccessor;
class GroupAccessor;
class Client;

namespace Share
{
using ResourceKey = std::tuple<Crypto::SymmetricKey, Trustchain::ResourceId>;
using ResourceKeys = std::vector<ResourceKey>;

struct KeyRecipients
{
  std::vector<Crypto::PublicEncryptionKey> recipientUserKeys;
  std::vector<Crypto::PublicEncryptionKey> recipientGroupKeys;
};

std::vector<uint8_t> makeKeyPublishToUser(
    BlockGenerator const& blockGenerator,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey);

std::vector<uint8_t> makeKeyPublishToGroup(
    BlockGenerator const& blockGenerator,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey);

tc::cotask<KeyRecipients> generateRecipientList(
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    std::vector<Trustchain::UserId> const& userIds,
    std::vector<Trustchain::GroupId> const& groupIds);

std::vector<std::vector<uint8_t>> generateShareBlocks(
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    BlockGenerator const& blockGenerator,
    ResourceKeys const& resourceKeys,
    KeyRecipients const& keyRecipients);

tc::cotask<void> share(
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    ResourceKeys const& resourceKeys,
    std::vector<Trustchain::UserId> const& userIds,
    std::vector<Trustchain::GroupId> const& groupIds);

tc::cotask<void> share(
    Crypto::PrivateEncryptionKey const& selfPrivateEncryptionKey,
    ResourceKeyStore const& resourceKeyStore,
    UserAccessor& userAccessor,
    GroupAccessor& groupAccessor,
    BlockGenerator const& blockGenerator,
    Client& client,
    std::vector<Trustchain::ResourceId> const& resourceIds,
    std::vector<Trustchain::UserId> const& recipientUserIds,
    std::vector<Trustchain::GroupId> const& groupIds);
}
}
