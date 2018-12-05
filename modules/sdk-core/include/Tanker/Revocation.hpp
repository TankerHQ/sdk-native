#pragma once

#include <Tanker/Actions/DeviceRevocation.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/User.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <tuple>
#include <vector>

namespace Tanker
{
class BlockGenerator;
class ContactStore;
class UserKeyStore;
class DeviceKeyStore;
class UserAccessor;
class Client;

namespace Revocation
{
tc::cotask<void> ensureDeviceIsFromUser(DeviceId const& deviceId,
                                        UserId const& selfUserId,
                                        ContactStore const& contactStore);

tc::cotask<User> getUserFromUserId(UserId const& selfUserId,
                                   ContactStore const& contactStore);

tc::cotask<Crypto::SealedPrivateEncryptionKey> encryptForPreviousUserKey(
    UserKeyStore const& userKeyStore,
    User const& user,
    Crypto::PublicEncryptionKey const& publicEncryptionKey);

tc::cotask<std::vector<EncryptedPrivateUserKey>> encryptPrivateKeyForDevices(
    User const& user,
    DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey);

tc::cotask<void> revokeDevice(DeviceId const& deviceId,
                              UserId const& userId,
                              ContactStore const& contactStore,
                              UserKeyStore const& userKeyStore,
                              BlockGenerator const& blockGenerator,
                              std::unique_ptr<Client> const& client);

Crypto::PrivateEncryptionKey decryptPrivateKeyForDevice(
    std::unique_ptr<DeviceKeyStore> const& deviceKeyStore,
    Crypto::SealedPrivateEncryptionKey const& encryptedPrivateEncryptionKey);

tc::cotask<void> onOtherDeviceRevocation(
    DeviceRevocation const& deviceRevocation,
    Entry const& entry,
    UserId const& selfUserId,
    DeviceId const& deviceId,
    ContactStore& contactStore,
    std::unique_ptr<DeviceKeyStore> const& deviceKeyStore,
    UserKeyStore& userKeyStore);
}
}
