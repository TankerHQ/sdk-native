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
class LocalUser;
struct User;
}

struct DeviceKeys;
class BlockGenerator;
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

tc::cotask<Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices>
encryptPrivateKeyForDevices(
    Users::User const& user,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey);

tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId,
                              Users::LocalUser const& localUser,
                              Users::ContactStore const& contactStore,
                              BlockGenerator const& blockGenerator,
                              std::unique_ptr<Client> const& client);

Crypto::PrivateEncryptionKey decryptPrivateKeyForDevice(
    DeviceKeys const& deviceKeys,
    Crypto::SealedPrivateEncryptionKey const& encryptedPrivateEncryptionKey);

tc::cotask<void> onOtherDeviceRevocation(
    Trustchain::Actions::DeviceRevocation const& deviceRevocation,
    Entry const& entry,
    Users::ContactStore& contactStore,
    Users::LocalUser& localUser);
}
}
