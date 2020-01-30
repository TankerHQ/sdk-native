#include <Tanker/Revocation.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Users/UserAccessor.hpp>

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
                                        Users::IUserAccessor& userAccessor)
{
  auto const result = TC_AWAIT(userAccessor.pull(gsl::make_span(&deviceId, 1)));
  if (!result.notFound.empty() || result.found.front().userId() != selfUserId)
    throw formatEx(
        Errc::InvalidArgument, TFMT("unknown device: {:s}"), deviceId);
}

tc::cotask<Users::User> getUserFromUserId(UserId const& selfUserId,
                                          Users::IUserAccessor& userAccessor)
{
  auto const result =
      TC_AWAIT(userAccessor.pull(gsl::make_span(&selfUserId, 1)));
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
    Users::User const& user,
    DeviceId const& deviceId,
    Crypto::PrivateEncryptionKey const& encryptionPrivateKey)
{
  DeviceRevocation::v2::SealedKeysForDevices userKeys;
  for (auto const& device : user.devices())
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

tc::cotask<void> revokeDevice(DeviceId const& deviceId,
                              TrustchainId const& trustchainId,
                              Users::LocalUser const& localUser,
                              Users::IUserAccessor& userAccessor,
                              std::unique_ptr<Client> const& client)
{
  TC_AWAIT(ensureDeviceIsFromUser(deviceId, localUser.userId(), userAccessor));
  auto const user =
      TC_AWAIT(getUserFromUserId(localUser.userId(), userAccessor));

  auto const newEncryptionKey = Crypto::makeEncryptionKeyPair();
  auto const oldPublicEncryptionKey = *user.userKey();

  auto const encryptedKeyForPreviousUserKey = Crypto::sealEncrypt(
      localUser.currentKeyPair().privateKey, newEncryptionKey.publicKey);

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
}
}
