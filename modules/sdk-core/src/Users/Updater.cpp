#include <Tanker/Users/Updater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/DeviceUnusable.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Verif/DeviceCreation.hpp>
#include <Tanker/Verif/Errors/ErrcCategory.hpp>
#include <Tanker/Verif/TrustchainCreation.hpp>

#include <range/v3/action/reverse.hpp>
#include <range/v3/algorithm/find_if.hpp>
#include <range/v3/iterator/operations.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/all.hpp>
#include <range/v3/view/concat.hpp>
#include <range/v3/view/reverse.hpp>
#include <range/v3/view/single.hpp>
#include <range/v3/view/slice.hpp>
#include <range/v3/view/transform.hpp>

#include <numeric>
#include <tuple>

TLOG_CATEGORY(UsersUpdater);

namespace Tanker::Users::Updater
{
using namespace Tanker::Trustchain::Actions;

Crypto::PublicSignatureKey extractTrustchainSignature(Trustchain::TrustchainId const& trustchainId,
                                                      Trustchain::Actions::TrustchainCreation const& trustchainCreation)
{
  return Verif::verifyTrustchainCreation(trustchainCreation, trustchainId).publicSignatureKey();
}

namespace
{
Crypto::EncryptionKeyPair checkedDecrypt(Crypto::SealedEncryptionKeyPair const& sealedKp,
                                         Crypto::EncryptionKeyPair const& kp)
{
  auto const [pubKey, sealedKey] = sealedKp;
  auto const decryptedKey = Crypto::sealDecrypt(sealedKey, kp);
  if (Crypto::derivePublicKey(decryptedKey) != pubKey)
    throw Errors::formatEx(Errors::Errc::InternalError, "public and private user key do not match");
  return {pubKey, decryptedKey};
}

auto decryptCurrentDeviceUserKey(Crypto::EncryptionKeyPair const& devEncKP,
                                 gsl::span<Crypto::SealedEncryptionKeyPair const> encryptedUserKeys)
{
  auto const selfEncKeyIt = ranges::find_if(
      encryptedUserKeys, &Crypto::PublicEncryptionKey::is_null, &Crypto::SealedEncryptionKeyPair::publicKey);

  if (selfEncKeyIt == encryptedUserKeys.end())
  {
    throw Errors::AssertionError("Did not find the encrypted user key for our device");
  }

  return std::make_pair(Crypto::makeEncryptionKeyPair(Crypto::sealDecrypt(selfEncKeyIt->sealedPrivateKey, devEncKP)),
                        ranges::distance(encryptedUserKeys.begin(), selfEncKeyIt));
}
}

Users::User applyDeviceCreationToUser(Trustchain::Actions::DeviceCreation const& dc,
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

std::optional<Crypto::SealedEncryptionKeyPair> extractEncryptedUserKey(DeviceCreation const& deviceCreation)
{
  if (auto dc3 = deviceCreation.get_if<DeviceCreation::v3>())
    return Crypto::SealedEncryptionKeyPair{{}, dc3->sealedPrivateUserEncryptionKey()};
  return std::nullopt;
}

std::tuple<Users::User, std::vector<Crypto::SealedEncryptionKeyPair>> processUserSealedKeys(
    Trustchain::DeviceId const& deviceId,
    DeviceKeys const& deviceKeys,
    Trustchain::Context const& context,
    gsl::span<Trustchain::UserAction const> actions)
{
  std::vector<Crypto::SealedEncryptionKeyPair> sealedKeys;

  std::optional<Users::User> user;
  bool foundThisDevice = false;
  for (auto const& action : actions)
  {
    if (auto const deviceCreation = boost::variant2::get_if<DeviceCreation>(&action))
    {
      auto const action = Verif::verifyDeviceCreation(*deviceCreation, context, user);
      user = applyDeviceCreationToUser(action, user);
      auto const& device = user->devices().back();
      if (device.id() == deviceId)
      {
        // These are very strange assertions, you could argue that they can't
        // fail. Yet we have seen those cases in production, so these
        // assertions will provide us with more information.
        if (device.publicEncryptionKey() != deviceKeys.encryptionKeyPair.publicKey)
          throw Errors::DeviceUnusable(
              fmt::format("found this device, but the public encryption key does not "
                          "match (device ID: {}, found key: {}, expected key: {})",
                          deviceId,
                          device.publicEncryptionKey(),
                          deviceKeys.encryptionKeyPair.publicKey));
        if (device.publicSignatureKey() != deviceKeys.signatureKeyPair.publicKey)
          throw Errors::DeviceUnusable(
              fmt::format("found this device, but the public signature key does not "
                          "match (device ID: {}, found key: {}, expected key: {})",
                          deviceId,
                          device.publicSignatureKey(),
                          deviceKeys.signatureKeyPair.publicKey));
        if (auto const extractedKeys = extractEncryptedUserKey(*deviceCreation))
          sealedKeys.push_back(*extractedKeys);
        foundThisDevice = true;
      }
      else if (device.publicEncryptionKey() == deviceKeys.encryptionKeyPair.publicKey)
        throw Errors::DeviceUnusable(
            fmt::format("found this device's public encryption key, but the "
                        "device id does not match (public encryption key: "
                        "{}, found device ID: {}, expected device ID: {})",
                        deviceKeys.encryptionKeyPair.publicKey,
                        device.id(),
                        deviceId));
      else if (device.publicSignatureKey() == deviceKeys.signatureKeyPair.publicKey)
        throw Errors::DeviceUnusable(
            fmt::format("found this device's public signature key, but the "
                        "device id does not match (public signature key: "
                        "{}, found device ID: {}, expected device ID: {})",
                        deviceKeys.signatureKeyPair.publicKey,
                        device.id(),
                        deviceId));
    }
  }
  if (!user.has_value())
    throw Errors::formatEx(Errors::Errc::InternalError, "We did not find our user");
  if (!foundThisDevice)
    throw Errors::DeviceUnusable(
        fmt::format("could not find this device during initial pull "
                    "(device ID: {}, public signature key: {})",
                    deviceId,
                    deviceKeys.signatureKeyPair.publicKey));

  return std::make_tuple(*user, sealedKeys);
}

std::vector<Crypto::EncryptionKeyPair> recoverUserKeys(
    Crypto::EncryptionKeyPair const& devEncKP, gsl::span<Crypto::SealedEncryptionKeyPair const> encryptedUserKeys)
{
  using namespace ranges;

  auto [deviceUserKeyPair, index] = decryptCurrentDeviceUserKey(devEncKP, encryptedUserKeys);

  // keys have to be decrypted in reverse order, as they are encrypted with
  // the next key
  // i.e. kp[0] is encrypted with kp[1]

  auto previousKeys = views::slice(encryptedUserKeys, 0, index) | views::reverse |
                      views::transform([kp = deviceUserKeyPair](auto const& sealedKey) mutable {
                        kp = checkedDecrypt(sealedKey, kp);
                        return kp;
                      }) |
                      // if we try to use views::reverse,it will reverse the transform_view, but
                      // since everything is lazy it will transform from the first key to the
                      // last, not the opposite!
                      to<std::vector> | actions::reverse;
  auto nextKeys =
      views::slice(encryptedUserKeys, index + 1, ranges::end) | views::transform(bind_back(checkedDecrypt, devEncKP));

  return views::concat(previousKeys, views::single(deviceUserKeyPair), nextKeys) | to<std::vector>;
}

std::tuple<Trustchain::Context, Users::User, std::vector<Crypto::EncryptionKeyPair>> processUserEntries(
    Trustchain::DeviceId const& deviceId,
    DeviceKeys const& deviceKeys,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::Actions::TrustchainCreation const& trustchainCreation,
    gsl::span<Trustchain::UserAction const> entries)
{
  if (entries.empty())
    throw Errors::formatEx(Errors::Errc::InternalError, "User's block list is too short");
  auto trustchainSignatureKey = extractTrustchainSignature(trustchainId, trustchainCreation);
  auto const context = Trustchain::Context{trustchainId, trustchainSignatureKey};
  auto [user, sealedKeys] = processUserSealedKeys(deviceId, deviceKeys, context, entries);
  auto userKeys = recoverUserKeys(deviceKeys.encryptionKeyPair, sealedKeys);
  return std::make_tuple(context, std::move(user), std::move(userKeys));
}
}
