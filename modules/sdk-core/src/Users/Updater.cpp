#include <Tanker/Users/Updater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/DeviceUnusable.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/DeviceRevocation.hpp>
#include <Tanker/Verif/Errors/ErrcCategory.hpp>
#include <Tanker/Verif/TrustchainCreation.hpp>

#include <numeric>
#include <tuple>

TLOG_CATEGORY(UsersUpdater);

namespace Tanker::Users::Updater
{
using namespace Tanker::Trustchain::Actions;

Crypto::PublicSignatureKey extractTrustchainSignature(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::Actions::TrustchainCreation const& trustchainCreation)
{
  return Verif::verifyTrustchainCreation(trustchainCreation, trustchainId)
      .publicSignatureKey();
}

namespace
{
Crypto::EncryptionKeyPair checkedDecrypt(
    Crypto::SealedEncryptionKeyPair const& sealedKp,
    Crypto::EncryptionKeyPair const& kp)
{
  auto const [pubKey, sealedKey] = sealedKp;
  auto const decryptedKey = Crypto::sealDecrypt(sealedKey, kp);
  if (Crypto::derivePublicKey(decryptedKey) != pubKey)
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "public and private user key do not match");
  return {pubKey, decryptedKey};
}
}

Users::User applyDeviceCreationToUser(
    Trustchain::Actions::DeviceCreation const& dc,
    std::optional<Users::User> previousUser)
{
  if (!previousUser.has_value())
    previousUser.emplace(Users::User{dc.userId(), {}, {}});
  previousUser->addDevice({Trustchain::DeviceId{dc.hash()},
                           dc.userId(),
                           dc.publicSignatureKey(),
                           dc.publicEncryptionKey(),
                           dc.isGhostDevice()});
  if (auto const v3 = dc.get_if<DeviceCreation::v3>())
    previousUser->setUserKey(v3->publicUserEncryptionKey());
  return *previousUser;
}

Users::User applyDeviceRevocationToUser(
    Trustchain::Actions::DeviceRevocation const& dr, Users::User previousUser)
{
  if (auto const v2 = dr.get_if<DeviceRevocation::v2>())
    previousUser.setUserKey(v2->publicEncryptionKey());
  previousUser.getDevice(dr.deviceId()).setRevoked();
  return previousUser;
}

std::optional<Crypto::SealedEncryptionKeyPair> extractEncryptedUserKey(
    DeviceCreation const& deviceCreation)
{
  if (auto dc3 = deviceCreation.get_if<DeviceCreation::v3>())
    return Crypto::SealedEncryptionKeyPair{
        {}, dc3->sealedPrivateUserEncryptionKey()};
  return std::nullopt;
}

std::optional<Crypto::SealedEncryptionKeyPair> extractEncryptedUserKey(
    DeviceRevocation const& deviceRevocation,
    Trustchain::DeviceId const& selfDeviceId)
{
  if (auto const dr2 = deviceRevocation.get_if<DeviceRevocation::v2>())
  {
    if (!selfDeviceId.is_null())
    {
      if (auto const encryptedPrivateKey =
              Revocation::findUserKeyFromDeviceSealedKeys(
                  selfDeviceId, dr2->sealedUserKeysForDevices()))
        return Crypto::SealedEncryptionKeyPair{dr2->publicEncryptionKey(),
                                               *encryptedPrivateKey};
      if (selfDeviceId == dr2->deviceId())
        throw formatEx(Errors::Errc::DeviceRevoked,
                       "Our device has been revoked");
    }
    return Crypto::SealedEncryptionKeyPair{dr2->previousPublicEncryptionKey(),
                                           dr2->sealedKeyForPreviousUserKey()};
  }
  return std::nullopt;
}

std::tuple<Users::User, std::vector<Crypto::SealedEncryptionKeyPair>>
processUserSealedKeys(Trustchain::DeviceId const& deviceId,
                      DeviceKeys const& deviceKeys,
                      Trustchain::Context const& context,
                      gsl::span<Trustchain::UserAction const> actions)
{
  std::vector<Crypto::SealedEncryptionKeyPair> sealedKeys;

  std::optional<Users::User> user;
  bool foundThisDevice = false;
  for (auto const& action : actions)
  {
    try
    {
      if (auto const deviceCreation =
              boost::variant2::get_if<DeviceCreation>(&action))
      {
        auto const action =
            Verif::verifyDeviceCreation(*deviceCreation, context, user);
        auto const extractedKeys = extractEncryptedUserKey(*deviceCreation);
        user = applyDeviceCreationToUser(action, user);
        auto const& device = user->devices().back();
        if (device.id() == deviceId)
        {
          // These are very strange assertions, you could argue that they can't
          // fail. Yet we have seen those cases in production, so these
          // assertions will provide us with more information.
          if (device.publicEncryptionKey() !=
              deviceKeys.encryptionKeyPair.publicKey)
            throw Errors::DeviceUnusable(fmt::format(
                "found this device, but the public encryption key does not "
                "match (device ID: {}, found key: {}, expected key: {})",
                deviceId,
                device.publicEncryptionKey(),
                deviceKeys.encryptionKeyPair.publicKey));
          if (device.publicSignatureKey() !=
              deviceKeys.signatureKeyPair.publicKey)
            throw Errors::DeviceUnusable(fmt::format(
                "found this device, but the public signature key does not "
                "match (device ID: {}, found key: {}, expected key: {})",
                deviceId,
                device.publicSignatureKey(),
                deviceKeys.signatureKeyPair.publicKey));
          if (extractedKeys)
            sealedKeys.push_back(*extractedKeys);
          foundThisDevice = true;
        }
        else if (device.publicEncryptionKey() ==
                 deviceKeys.encryptionKeyPair.publicKey)
          throw Errors::DeviceUnusable(
              fmt::format("found this device's public encryption key, but the "
                          "device id does not match (public encryption key: "
                          "{}, found device ID: {}, expected device ID: {})",
                          deviceKeys.encryptionKeyPair.publicKey,
                          device.id(),
                          deviceId));
        else if (device.publicSignatureKey() ==
                 deviceKeys.signatureKeyPair.publicKey)
          throw Errors::DeviceUnusable(
              fmt::format("found this device's public signature key, but the "
                          "device id does not match (public signature key: "
                          "{}, found device ID: {}, expected device ID: {})",
                          deviceKeys.signatureKeyPair.publicKey,
                          device.id(),
                          deviceId));
      }
      else if (auto const deviceRevocation =
                   boost::variant2::get_if<DeviceRevocation>(&action))
      {
        auto const action =
            Verif::verifyDeviceRevocation(*deviceRevocation, user);
        if (auto const extractedKeys =
                extractEncryptedUserKey(*deviceRevocation, deviceId))
          sealedKeys.push_back(*extractedKeys);
        user = applyDeviceRevocationToUser(action, *user);
      }
    }
    catch (Errors::Exception const& err)
    {
      if (err.errorCode().category() == Tanker::Verif::ErrcCategory())
        TERROR("skipping invalid block {}: {}",
               Trustchain::getHash(action),
               err.what());
      else
        throw;
    }
  }
  if (!user.has_value())
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "We did not find our user");
  if (!foundThisDevice)
    throw Errors::DeviceUnusable(
        fmt::format("could not find this device during initial pull "
                    "(device ID: {}, public signature key: {})",
                    deviceId,
                    deviceKeys.signatureKeyPair.publicKey));

  return std::make_tuple(*user, sealedKeys);
}

std::vector<Crypto::EncryptionKeyPair> recoverUserKeys(
    Crypto::EncryptionKeyPair const& devEncKP,
    gsl::span<Crypto::SealedEncryptionKeyPair const> encryptedUserKeys)
{
  auto const firstEncKeys = encryptedUserKeys.begin();
  auto const lastEncKeys = encryptedUserKeys.end();

  // First we find our key in the encrypted userkeys.
  auto selfEncKeyIt =
      std::find_if(firstEncKeys, lastEncKeys, [](auto const& encryptedUserKey) {
        return encryptedUserKey.publicKey.is_null();
      });

  if (selfEncKeyIt == lastEncKeys)
    throw Errors::AssertionError(
        "Did not find the encrypted user key for our device");

  std::vector<Crypto::EncryptionKeyPair> userKeys(encryptedUserKeys.size());
  auto const selfUserKeyIt = userKeys.begin() + (selfEncKeyIt - firstEncKeys);

  // Then we decrypt our user key.
  *selfUserKeyIt = Crypto::makeEncryptionKeyPair(
      Crypto::sealDecrypt(selfEncKeyIt->sealedPrivateKey, devEncKP));

  // Second we decrypt the user keys before our device creation starting
  // with the current user key in reverse order.
  std::transform(std::make_reverse_iterator(selfEncKeyIt),
                 encryptedUserKeys.rend(),
                 std::make_reverse_iterator(selfUserKeyIt),
                 [kp = *selfUserKeyIt](auto const& sealedKey) mutable {
                   kp = checkedDecrypt(sealedKey, kp);
                   return kp;
                 });
  // Third we decrypt the user keys with our device keys.
  std::transform(std::next(selfEncKeyIt),
                 encryptedUserKeys.end(),
                 std::next(selfUserKeyIt),
                 [&](auto const& sealedKey) {
                   return checkedDecrypt(sealedKey, devEncKP);
                 });
  return userKeys;
}

std::tuple<Trustchain::Context,
           Users::User,
           std::vector<Crypto::EncryptionKeyPair>>
processUserEntries(
    Trustchain::DeviceId const& deviceId,
    DeviceKeys const& deviceKeys,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::Actions::TrustchainCreation const& trustchainCreation,
    gsl::span<Trustchain::UserAction const> entries)
{
  if (entries.empty())
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "User's block list is too short");
  auto trustchainSignatureKey =
      extractTrustchainSignature(trustchainId, trustchainCreation);
  auto const context =
      Trustchain::Context{trustchainId, trustchainSignatureKey};
  auto [user, sealedKeys] =
      processUserSealedKeys(deviceId, deviceKeys, context, entries);
  auto userKeys = recoverUserKeys(deviceKeys.encryptionKeyPair, sealedKeys);
  return std::make_tuple(context, std::move(user), std::move(userKeys));
}
}
