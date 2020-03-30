#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/ProvisionalUsers/PublicUser.hpp>
#include <Tanker/ResourceKeys/KeysResult.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Users/Device.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <tuple>
#include <vector>

namespace Tanker::Users
{
class IUserAccessor;
}

namespace Tanker
{
class Client;

namespace Groups
{
class IAccessor;
}

namespace Share
{
struct KeyRecipients
{
  std::vector<Crypto::PublicEncryptionKey> recipientUserKeys;
  std::vector<ProvisionalUsers::PublicUser> recipientProvisionalUserKeys;
  std::vector<Crypto::PublicEncryptionKey> recipientGroupKeys;
};

Trustchain::ClientEntry makeKeyPublishToUser(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey);

Trustchain::ClientEntry makeKeyPublishToGroup(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey);

Trustchain::ClientEntry makeKeyPublishToProvisionalUser(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ProvisionalUsers::PublicUser const& recipientProvisionalUser,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& resourceKey);

tc::cotask<KeyRecipients> generateRecipientList(
    Users::IUserAccessor& userAccessor,
    Groups::IAccessor& groupAccessor,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds);

std::vector<std::vector<uint8_t>> generateShareBlocks(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& signatureKey,
    ResourceKeys::KeysResult const& resourceKeys,
    KeyRecipients const& keyRecipients);

tc::cotask<void> share(Users::IUserAccessor& userAccessor,
                       Groups::IAccessor& groupAccessor,
                       Trustchain::TrustchainId const& trustchainId,
                       Trustchain::DeviceId const& deviceId,
                       Crypto::PrivateSignatureKey const& signatureKey,
                       Client& client,
                       ResourceKeys::KeysResult const& resourceKeys,
                       std::vector<SPublicIdentity> const& publicIdentities,
                       std::vector<SGroupId> const& groupIds);
}
}
