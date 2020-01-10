#include <Tanker/Revocation.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/User.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <algorithm>
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
  if (!user->userKey())
    throw formatEx(Errc::InternalError, "user should always have a user key");

  TC_RETURN(*user);
}

tc::cotask<Crypto::SealedPrivateEncryptionKey> encryptForPreviousUserKey(
    Users::LocalUser const& localUser,
    Users::User const& user,
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const previousEncryptionPrivateKey =
      TC_AWAIT(localUser.findKeyPair(*user.userKey()));

  if (!previousEncryptionPrivateKey)
    throw Errors::formatEx(Errors::Errc::InternalError,
                           TFMT("cannot find user key for public key: {:s}"),
                           *user.userKey());
  auto const encryptedKeyForPreviousUserKey = Crypto::sealEncrypt(
      previousEncryptionPrivateKey->privateKey, publicEncryptionKey);

  TC_RETURN(encryptedKeyForPreviousUserKey);
}

DeviceRevocation::v2::SealedKeysForDevices encryptPrivateKeyForDevices(
    Users::User const& user,
    DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey)
{
  DeviceRevocation::v2::SealedKeysForDevices userKeys;
  for (auto const& device : user.devices())
  {
    if (device.id() != deviceId && device.revokedAtBlkIndex() == std::nullopt)
    {
      Crypto::SealedPrivateEncryptionKey sealedEncryptedKey{Crypto::sealEncrypt(
          encryptionPrivateKey, device.publicEncryptionKey())};
      userKeys.emplace_back(device.id(), sealedEncryptedKey);
    }
  }

  return userKeys;
}

tc::cotask<void> revokeDevice(DeviceId const& deviceId,
                              TrustchainId const& trustchainId,
                              Users::LocalUser const& localUser,
                              Users::ContactStore const& contactStore,
                              std::unique_ptr<Client> const& client)
{
  TC_AWAIT(ensureDeviceIsFromUser(deviceId, localUser.userId(), contactStore));
  auto const user =
      TC_AWAIT(getUserFromUserId(localUser.userId(), contactStore));

  auto const newEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto const oldPublicEncryptionKey = *user.userKey();

  auto const encryptedKeyForPreviousUserKey = TC_AWAIT(
      encryptForPreviousUserKey(localUser, user, newEncryptionKey.publicKey));

  auto const userKeys =
      encryptPrivateKeyForDevices(user, deviceId, newEncryptionKey.privateKey);

  auto const clientEntry = Users::revokeDeviceEntry(
      trustchainId,
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey,
      deviceId,
      newEncryptionKey.publicKey,
      encryptedKeyForPreviousUserKey,
      oldPublicEncryptionKey,
      userKeys);

  TC_AWAIT(client->pushBlock(Serialization::serialize(clientEntry)));
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
  auto const sealedPrivateUserKey =
      std::find_if(keyForDevices.begin(),
                   keyForDevices.end(),
                   [&](auto const& encryptedUserKey) {
                     return encryptedUserKey.first == deviceId;
                   });
  if (sealedPrivateUserKey == keyForDevices.end())
    return std::nullopt;
  return sealedPrivateUserKey->second;
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
      auto decryptedUserPrivateKey = findUserKeyFromDeviceSealedKeys(
          localUser.deviceId(), deviceRevocation2->sealedUserKeysForDevices());

      assert(decryptedUserPrivateKey.has_value() &&
             "Did not find our deviceId in sealedKeys' DeviceRevocation");

      auto const privateKey = decryptPrivateKeyForDevice(
          localUser.deviceKeys(), decryptedUserPrivateKey.value());
      TC_AWAIT(localUser.insertUserKey(Crypto::EncryptionKeyPair{
          deviceRevocation2->publicEncryptionKey(), privateKey}));
    }
  }
}
}
}
