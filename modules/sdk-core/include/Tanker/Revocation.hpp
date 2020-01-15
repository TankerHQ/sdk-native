#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <optional>
#include <tuple>
#include <vector>

namespace Tanker
{
namespace Users
{
class ContactStore;
class LocalUser;
struct User;
}

struct DeviceKeys;
class Client;

namespace Revocation
{
tc::cotask<void> ensureDeviceIsFromUser(
    Trustchain::DeviceId const& deviceId,
    Trustchain::UserId const& selfUserId,
    Users::ContactStore const& contactStore);

tc::cotask<Users::User> getUserFromUserId(
    Trustchain::UserId const& selfUserId,
    Users::ContactStore const& contactStore);

tc::cotask<Crypto::SealedPrivateEncryptionKey> encryptForPreviousUserKey(
    Users::LocalUser const& localUser,
    Users::User const& user,
    Crypto::PublicEncryptionKey const& publicEncryptionKey);

using SealedKeysForDevices =
    Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices;

SealedKeysForDevices encryptPrivateKeyForDevices(
    Users::User const& user,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey);

tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId,
                              Trustchain::TrustchainId const& trustchainId,
                              Users::LocalUser const& localUser,
                              Users::ContactStore const& contactStore,
                              std::unique_ptr<Client> const& client);

Crypto::PrivateEncryptionKey decryptPrivateKeyForDevice(
    DeviceKeys const& deviceKeys,
    Crypto::SealedPrivateEncryptionKey const& encryptedPrivateEncryptionKey);

std::optional<Crypto::SealedPrivateEncryptionKey>
findUserKeyFromDeviceSealedKeys(Trustchain::DeviceId const& deviceId,
                                SealedKeysForDevices const& keyForDevices);

tc::cotask<void> onOtherDeviceRevocation(
    Trustchain::Actions::DeviceRevocation const& deviceRevocation,
    Entry const& entry,
    Users::ContactStore& contactStore,
    Users::LocalUser& localUser);
}
}
