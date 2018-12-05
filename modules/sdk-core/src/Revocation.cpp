#include <Tanker/Revocation.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DeviceKeyStore.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <vector>

namespace Tanker
{
namespace Revocation
{

tc::cotask<void> ensureDeviceIsFromUser(DeviceId const& deviceId,
                                        UserId const& selfUserId,
                                        ContactStore const& contactStore)
{
  auto const userId = TC_AWAIT(contactStore.findUserIdByDeviceId(deviceId));
  if (!userId || userId != selfUserId)
  {
    throw Error::formatEx<Error::DeviceNotFound>(
        fmt::format("Unknown device: {:s}", base64::encode(deviceId)));
  }
}

tc::cotask<User> getUserFromUserId(UserId const& selfUserId,
                                   ContactStore const& contactStore)
{
  auto const user = TC_AWAIT(contactStore.findUser(selfUserId));
  if (!user)
  {
    throw Error::InternalError(
        "User associated with given deviceId should be a valid user");
  }
  if (!user->userKey)
  {
    throw Error::InternalError("User should always have a userKey");
  }

  TC_RETURN(*user);
}

tc::cotask<Crypto::SealedPrivateEncryptionKey> encryptForPreviousUserKey(
    UserKeyStore const& userKeyStore,
    User const& user,
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const previousEncryptionPrivateKey =
      TC_AWAIT(userKeyStore.getKeyPair(*user.userKey));
  auto const encryptedKeyForPreviousUserKey = Crypto::sealEncrypt(
      previousEncryptionPrivateKey.privateKey, publicEncryptionKey);

  TC_RETURN(encryptedKeyForPreviousUserKey);
}

tc::cotask<std::vector<EncryptedPrivateUserKey>> encryptPrivateKeyForDevices(
    User const& user,
    DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey)
{
  std::vector<EncryptedPrivateUserKey> userKeys;
  for (auto const& device : user.devices)
  {
    if (device.id != deviceId)
    {
      Crypto::SealedPrivateEncryptionKey sealedEncryptedKey{Crypto::sealEncrypt(
          encryptionPrivateKey, device.publicEncryptionKey)};
      userKeys.push_back(
          EncryptedPrivateUserKey{device.id, sealedEncryptedKey});
    }
  }

  TC_RETURN(userKeys);
}

tc::cotask<void> revokeDevice(DeviceId const& deviceId,
                              UserId const& userId,
                              ContactStore const& contactStore,
                              UserKeyStore const& userKeyStore,
                              BlockGenerator const& blockGenerator,
                              std::unique_ptr<Client> const& client)
{
  TC_AWAIT(ensureDeviceIsFromUser(deviceId, userId, contactStore));
  auto const user = TC_AWAIT(getUserFromUserId(userId, contactStore));

  auto const newEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto const oldPublicEncryptionKey = *user.userKey;

  auto const encryptedKeyForPreviousUserKey =
      TC_AWAIT(encryptForPreviousUserKey(
          userKeyStore, user, newEncryptionKey.publicKey));

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
    std::unique_ptr<DeviceKeyStore> const& deviceKeyStore,
    Crypto::SealedPrivateEncryptionKey const& encryptedPrivateEncryptionKey)
{
  auto const deviceEncryptionKeyPair = deviceKeyStore->encryptionKeyPair();
  auto const decryptedUserPrivateKey =
      Crypto::PrivateEncryptionKey{Crypto::sealDecrypt(
          encryptedPrivateEncryptionKey, deviceEncryptionKeyPair)};
  return decryptedUserPrivateKey;
}

tc::cotask<void> onOtherDeviceRevocation(
    DeviceRevocation const& deviceRevocation,
    Entry const& entry,
    UserId const& selfUserId,
    DeviceId const& deviceId,
    ContactStore& contactStore,
    std::unique_ptr<DeviceKeyStore> const& deviceKeyStore,
    UserKeyStore& userKeyStore)
{
  TC_AWAIT(contactStore.revokeDevice(deviceRevocation.deviceId(), entry.index));

  if (auto const& deviceRevocation2 =
          mpark::get_if<DeviceRevocation2>(&deviceRevocation.variant()))
  {
    auto const userId = TC_AWAIT(
        contactStore.findUserIdByDeviceId(deviceRevocation2->deviceId));
    TC_AWAIT(contactStore.rotateContactPublicEncryptionKey(
        *userId, deviceRevocation2->publicEncryptionKey));
    assert(userId.has_value() &&
           "Device revocation has been verified, userId should exists");
    // deviceId is null for the first pass where the device has not been created
    if (*userId == selfUserId && !deviceId.is_null())
    {
      auto const encryptedPrivateUserKey =
          std::find_if(deviceRevocation2->userKeys.begin(),
                       deviceRevocation2->userKeys.end(),
                       [deviceId](auto const& encryptedUserKey) {
                         return encryptedUserKey.deviceId == deviceId;
                       });

      assert(
          encryptedPrivateUserKey != deviceRevocation2->userKeys.end() &&
          "Device revocation has been revoked deviceId should belong to user");
      auto const decryptedUserPrivateKey = decryptPrivateKeyForDevice(
          deviceKeyStore, encryptedPrivateUserKey->privateEncryptionKey);

      TC_AWAIT(userKeyStore.putPrivateKey(
          deviceRevocation2->publicEncryptionKey, decryptedUserPrivateKey));
    }
  }
}
}
}
