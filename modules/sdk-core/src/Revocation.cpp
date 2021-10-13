#include <Tanker/Revocation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <range/v3/algorithm/find.hpp>

#include <vector>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker
{
namespace Revocation
{

tc::cotask<void> ensureDeviceIsFromUser(DeviceId const& deviceId,
                                        UserId const& selfUserId,
                                        Users::IUserAccessor& userAccessor)
{
  auto const result = TC_AWAIT(userAccessor.pull({deviceId}));
  if (!result.notFound.empty() || result.found.front().userId() != selfUserId)
    throw formatEx(
        Errc::InvalidArgument, FMT_STRING("unknown device: {:s}"), deviceId);
}

tc::cotask<Users::User> getUserFromUserId(UserId const& selfUserId,
                                          Users::IUserAccessor& userAccessor)
{
  auto const result = TC_AWAIT(userAccessor.pull({selfUserId}));
  if (!result.notFound.empty())
    throw formatEx(
        Errc::InternalError,
        "user associated with given deviceId should be a valid user");
  auto const& user = result.found.front();
  if (!user.userKey())
    throw formatEx(Errc::InternalError, "user should always have a user key");

  TC_RETURN(user);
}

DeviceRevocation::v2::SealedKeysForDevices encryptPrivateKeyForDevices(
    gsl::span<Users::Device const> devices,
    DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey)
{
  DeviceRevocation::v2::SealedKeysForDevices userKeys;
  for (auto const& device : devices)
  {
    if (device.id() != deviceId && !device.isRevoked())
    {
      Crypto::SealedPrivateEncryptionKey sealedEncryptedKey{Crypto::sealEncrypt(
          encryptionPrivateKey, device.publicEncryptionKey())};
      userKeys.emplace_back(device.id(), sealedEncryptedKey);
    }
  }

  return userKeys;
}

Trustchain::Actions::DeviceRevocation2 makeRevokeDeviceAction(
    Trustchain::DeviceId const& targetDeviceId,
    Trustchain::TrustchainId const& trustchainId,
    Users::LocalUser const& localUser,
    gsl::span<Users::Device const> userDevices,
    Crypto::EncryptionKeyPair const& newUserKey)
{
  auto const& oldUserKey = localUser.currentKeyPair();
  auto const encryptedKeyForPreviousUserKey =
      Crypto::sealEncrypt(oldUserKey.privateKey, newUserKey.publicKey);

  auto const sealedUserKeys = encryptPrivateKeyForDevices(
      userDevices, targetDeviceId, newUserKey.privateKey);
  return Users::createRevokeDeviceAction(
      trustchainId,
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey,
      targetDeviceId,
      newUserKey.publicKey,
      encryptedKeyForPreviousUserKey,
      oldUserKey.publicKey,
      sealedUserKeys);
}

tc::cotask<void> revokeDevice(DeviceId const& deviceId,
                              TrustchainId const& trustchainId,
                              Users::LocalUser const& localUser,
                              Users::IUserAccessor& userAccessor,
                              Users::IRequester& requester)
{
  TC_AWAIT(ensureDeviceIsFromUser(deviceId, localUser.userId(), userAccessor));
  auto const user =
      TC_AWAIT(getUserFromUserId(localUser.userId(), userAccessor));

  auto const newUserKey = Crypto::makeEncryptionKeyPair();

  auto clientEntry = makeRevokeDeviceAction(
      deviceId, trustchainId, localUser, user.devices(), newUserKey);
  TC_AWAIT(requester.revokeDevice(clientEntry));
}

Crypto::PrivateEncryptionKey decryptPrivateKeyForDevice(
    DeviceKeys const& deviceKeys,
    Crypto::SealedPrivateEncryptionKey const& encryptedPrivateEncryptionKey)
{
  auto const deviceEncryptionKeyPair = deviceKeys.encryptionKeyPair;
  auto const decryptedUserPrivateKey =
      Crypto::PrivateEncryptionKey{Crypto::sealDecrypt(
          encryptedPrivateEncryptionKey, deviceEncryptionKeyPair)};
  return decryptedUserPrivateKey;
}

std::optional<Crypto::SealedPrivateEncryptionKey>
findUserKeyFromDeviceSealedKeys(Trustchain::DeviceId const& deviceId,
                                SealedKeysForDevices const& keyForDevices)
{
  auto const sealedPrivateUserKey = ranges::find(
      keyForDevices, deviceId, &SealedKeysForDevices::value_type::first);
  if (sealedPrivateUserKey == keyForDevices.end())
    return std::nullopt;
  return sealedPrivateUserKey->second;
}
}
}
