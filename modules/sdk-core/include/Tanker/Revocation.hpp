#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <cstdint>
#include <optional>
#include <tuple>
#include <vector>

namespace Tanker
{
namespace Users
{
class IUserAccessor;
class IRequester;
class LocalUser;
class User;
class Device;
}

struct DeviceKeys;

namespace Revocation
{
tc::cotask<void> ensureDeviceIsFromUser(Trustchain::DeviceId const& deviceId,
                                        Trustchain::UserId const& selfUserId,
                                        Users::IUserAccessor& userAccessor);

tc::cotask<Users::User> getUserFromUserId(Trustchain::UserId const& selfUserId,
                                          Users::IUserAccessor& userAccessor);

using SealedKeysForDevices =
    Trustchain::Actions::DeviceRevocation::v2::SealedKeysForDevices;

SealedKeysForDevices encryptPrivateKeyForDevices(
    gsl::span<Users::Device const> devices,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey);

tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId,
                              Trustchain::TrustchainId const& trustchainId,
                              Users::LocalUser const& localUser,
                              Users::IUserAccessor& userAccessor,
                              Users::IRequester& requester);

Trustchain::Actions::DeviceRevocation2 makeRevokeDeviceAction(
    Trustchain::DeviceId const& targetDeviceId,
    Trustchain::TrustchainId const& trustchainId,
    Users::LocalUser const& localUser,
    gsl::span<Users::Device const> userDevices,
    Crypto::EncryptionKeyPair const& newUserKey);

Crypto::PrivateEncryptionKey decryptPrivateKeyForDevice(
    DeviceKeys const& deviceKeys,
    Crypto::SealedPrivateEncryptionKey const& encryptedPrivateEncryptionKey);

std::optional<Crypto::SealedPrivateEncryptionKey>
findUserKeyFromDeviceSealedKeys(Trustchain::DeviceId const& deviceId,
                                SealedKeysForDevices const& keyForDevices);
}
}
