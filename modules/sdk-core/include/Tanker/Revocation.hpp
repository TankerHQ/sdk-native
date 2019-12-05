#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <tuple>
#include <vector>

namespace Tanker
{
namespace Users
{
class ContactStore;
class UserKeyStore;
struct User;
}

class BlockGenerator;
class DeviceKeyStore;
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
    Users::UserKeyStore const& userKeyStore,
    Users::User const& user,
    Crypto::PublicEncryptionKey const& publicEncryptionKey);

tc::cotask<Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices>
encryptPrivateKeyForDevices(
    Users::User const& user,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey);

tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId,
                              Trustchain::UserId const& userId,
                              Users::ContactStore const& contactStore,
                              Users::UserKeyStore const& userKeyStore,
                              BlockGenerator const& blockGenerator,
                              std::unique_ptr<Client> const& client);

Crypto::PrivateEncryptionKey decryptPrivateKeyForDevice(
    std::unique_ptr<DeviceKeyStore> const& deviceKeyStore,
    Crypto::SealedPrivateEncryptionKey const& encryptedPrivateEncryptionKey);

tc::cotask<void> onOtherDeviceRevocation(
    Trustchain::Actions::DeviceRevocation const& deviceRevocation,
    Entry const& entry,
    Trustchain::UserId const& selfUserId,
    Trustchain::DeviceId const& deviceId,
    Users::ContactStore& contactStore,
    std::unique_ptr<DeviceKeyStore> const& deviceKeyStore,
    Users::UserKeyStore& userKeyStore);
}
}
