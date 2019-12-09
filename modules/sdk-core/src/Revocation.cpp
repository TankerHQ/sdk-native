#include <Tanker/Revocation.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/User.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <algorithm>
#include <vector>

using Tanker::Trustchain::UserId;
using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker
{
namespace Revocation
{

tc::cotask<void> ensureDeviceIsFromUser(Trustchain::DeviceId const& deviceId,
                                        UserId const& selfUserId,
                                        Users::ContactStore const& contactStore)
{
  auto const userId = TC_AWAIT(contactStore.findUserIdByDeviceId(deviceId));
  if (!userId || userId != selfUserId)
  {
    throw formatEx(
        Errc::InvalidArgument, TFMT("unknown device: {:s}"), deviceId);
  }
}

tc::cotask<Users::User> getUserFromUserId(
    UserId const& selfUserId, Users::ContactStore const& contactStore)
{
  auto const user = TC_AWAIT(contactStore.findUser(selfUserId));
  if (!user)
  {
    throw formatEx(
        Errc::InternalError,
        "user associated with given deviceId should be a valid user");
  }
  if (!user->userKey)
    throw formatEx(Errc::InternalError, "user should always have a user key");

  TC_RETURN(*user);
}

tc::cotask<Crypto::SealedPrivateEncryptionKey> encryptForPreviousUserKey(
    Users::LocalUser const& localUser,
    Users::User const& user,
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const previousEncryptionPrivateKey =
      TC_AWAIT(localUser.findKeyPair(*user.userKey));

  if (!previousEncryptionPrivateKey)
    throw Errors::formatEx(Errors::Errc::InternalError,
                           TFMT("cannot find user key for public key: {:s}"),
                           *user.userKey);
  auto const encryptedKeyForPreviousUserKey = Crypto::sealEncrypt(
      previousEncryptionPrivateKey->privateKey, publicEncryptionKey);

  TC_RETURN(encryptedKeyForPreviousUserKey);
}

tc::cotask<DeviceRevocation::v2::SealedKeysForDevices>
encryptPrivateKeyForDevices(
    Users::User const& user,
    Trustchain::DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey)
{
  DeviceRevocation::v2::SealedKeysForDevices userKeys;
  for (auto const& device : user.devices)
  {
    if (device.id != deviceId && device.revokedAtBlkIndex == std::nullopt)
    {
      Crypto::SealedPrivateEncryptionKey sealedEncryptedKey{Crypto::sealEncrypt(
          encryptionPrivateKey, device.publicEncryptionKey)};
      userKeys.emplace_back(device.id, sealedEncryptedKey);
    }
  }

  TC_RETURN(userKeys);
}

tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId,
                              Users::LocalUser const& localUser,
                              Users::ContactStore const& contactStore,
                              BlockGenerator const& blockGenerator,
                              std::unique_ptr<Client> const& client)
{
  TC_AWAIT(ensureDeviceIsFromUser(deviceId, localUser.userId(), contactStore));
  auto const user =
      TC_AWAIT(getUserFromUserId(localUser.userId(), contactStore));

  auto const newEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto const oldPublicEncryptionKey = *user.userKey;

  auto const encryptedKeyForPreviousUserKey = TC_AWAIT(
      encryptForPreviousUserKey(localUser, user, newEncryptionKey.publicKey));

  auto const userKeys = TC_AWAIT(
      encryptPrivateKeyForDevices(user, deviceId, newEncryptionKey.privateKey));

  auto const block =
      blockGenerator.revokeDevice2(deviceId,
                                   newEncryptionKey.publicKey,
                                   oldPublicEncryptionKey,
                                   encryptedKeyForPreviousUserKey,
                                   userKeys);

  TC_AWAIT(client->pushBlock(block));
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

tc::cotask<void> onOtherDeviceRevocation(
    DeviceRevocation const& deviceRevocation,
    Entry const& entry,
    Users::ContactStore& contactStore,
    Users::LocalUser& localUser)
{
  TC_AWAIT(contactStore.revokeDevice(deviceRevocation.deviceId(), entry.index));

  if (auto const deviceRevocation2 =
          deviceRevocation.get_if<DeviceRevocation2>())
  {
    auto const userId = TC_AWAIT(
        contactStore.findUserIdByDeviceId(deviceRevocation2->deviceId()));
    TC_AWAIT(contactStore.rotateContactPublicEncryptionKey(
        *userId, deviceRevocation2->publicEncryptionKey()));
    assert(userId.has_value() &&
           "Device revocation has been verified, userId should exists");
    // deviceId is null for the first pass where the device has not been created
    if (*userId == localUser.userId() && !localUser.deviceId().is_null())
    {
      auto const sealedUserKeysForDevices =
          deviceRevocation2->sealedUserKeysForDevices();
      auto const sealedPrivateUserKey =
          std::find_if(sealedUserKeysForDevices.begin(),
                       sealedUserKeysForDevices.end(),
                       [&](auto const& encryptedUserKey) {
                         return encryptedUserKey.first == localUser.deviceId();
                       });

      assert(
          sealedPrivateUserKey != sealedUserKeysForDevices.end() &&
          "Device revocation has been revoked deviceId should belong to user");
      auto const decryptedUserPrivateKey = decryptPrivateKeyForDevice(
          localUser.deviceKeys(), sealedPrivateUserKey->second);

      TC_AWAIT(localUser.insertUserKey(Crypto::EncryptionKeyPair{
          deviceRevocation2->publicEncryptionKey(), decryptedUserPrivateKey}));
    }
  }
}
}
}
