#include <Tanker/Users/Updater.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Users/ContactStore.hpp>
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
bool operator==(SealedUserKey const& l, SealedUserKey const r)
{
  return std::tie(l.publicKey, l.sealedKey) ==
         std::tie(r.publicKey, r.sealedKey);
}

bool operator!=(SealedUserKey const& l, SealedUserKey const r)
{
  return !(l == r);
}

Crypto::PublicSignatureKey extractTrustchainSignature(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::ServerEntry const& serverEntry)
{
  if (!serverEntry.action().holds_alternative<TrustchainCreation>())
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "Entry not a trustchainCreation block");

  return Verif::verifyTrustchainCreation(serverEntry, trustchainId)
      .action.get<TrustchainCreation>()
      .publicSignatureKey();
}

namespace
{

Crypto::EncryptionKeyPair checkedDecrypt(SealedUserKey const& sealedKp,
                                         Crypto::EncryptionKeyPair const& kp)
{
  auto const& [pubKey, sealedKey] = sealedKp;
  auto const decryptedKey = Crypto::sealDecrypt(sealedKey, kp);
  if (Crypto::derivePublicKey(decryptedKey) != pubKey)
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "public and private user key do not match");
  return {pubKey, decryptedKey};
}

Users::Device extractDevice(Entry const& entry, DeviceCreation const& dc)
{
  return Users::Device(Trustchain::DeviceId{entry.hash},
                       dc.userId(),
                       entry.index,
                       dc.isGhostDevice(),
                       dc.publicSignatureKey(),
                       dc.publicEncryptionKey());
}
}

std::optional<std::tuple<Crypto::PublicEncryptionKey, SealedUserKey>>
extractEncryptedUserKey(DeviceCreation const& deviceCreation)
{
  if (auto dc3 = deviceCreation.get_if<DeviceCreation::v3>())
    return std::make_tuple(
        dc3->publicUserEncryptionKey(),
        SealedUserKey{{}, dc3->sealedPrivateUserEncryptionKey()});
  return std::nullopt;
}

std::optional<std::tuple<Crypto::PublicEncryptionKey, SealedUserKey>>
extractEncryptedUserKey(DeviceRevocation const& deviceRevocation,
                        Trustchain::DeviceId const& selfDeviceId)
{
  if (auto const dr2 = deviceRevocation.get_if<DeviceRevocation::v2>())
  {
    if (!selfDeviceId.is_null())
    {
      if (auto const encryptedPrivateKey =
              Revocation::findUserKeyFromDeviceSealedKeys(
                  selfDeviceId, dr2->sealedUserKeysForDevices()))
        return std::make_tuple(
            dr2->publicEncryptionKey(),
            SealedUserKey{dr2->publicEncryptionKey(), *encryptedPrivateKey});
      if (selfDeviceId == dr2->deviceId())
        throw formatEx(Errors::Errc::DeviceRevoked,
                       "Our device has been revoked");
    }
    return std::make_tuple(dr2->publicEncryptionKey(),
                           SealedUserKey{dr2->previousPublicEncryptionKey(),
                                         dr2->sealedKeyForPreviousUserKey()});
  }
  return std::nullopt;
}

std::tuple<Users::User, std::vector<SealedUserKey>> extractUserSealedKeys(
    DeviceKeys const& deviceKeys,
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& trustchainPubSigKey,
    gsl::span<Trustchain::ServerEntry const> entries)
{
  std::vector<SealedUserKey> sealedKeys;

  Users::User user;
  Trustchain::DeviceId selfDeviceId;
  for (auto const& serverEntry : entries)
  {
    try
    {
      if (auto const deviceCreation =
              serverEntry.action().get_if<DeviceCreation>())
      {
        auto const entry = Verif::verifyDeviceCreation(
            serverEntry, trustchainId, trustchainPubSigKey, user);
        auto const device = extractDevice(entry, *deviceCreation);
        user.devices.push_back(device);
        auto const extractedKeys = extractEncryptedUserKey(*deviceCreation);
        if (extractedKeys)
          user.userKey = std::get<Crypto::PublicEncryptionKey>(*extractedKeys);
        if (device.publicSignatureKey == deviceKeys.signatureKeyPair.publicKey)
        {
          selfDeviceId = device.id;
          user.id = device.userId;
          if (extractedKeys)
            sealedKeys.push_back(std::get<SealedUserKey>(*extractedKeys));
        }
      }
      else if (auto const deviceRevocation =
                   serverEntry.action().get_if<DeviceRevocation>())
      {
        auto const entry = Verif::verifyDeviceRevocation(serverEntry, user);
        if (auto const extractedKeys =
                extractEncryptedUserKey(*deviceRevocation, selfDeviceId))
        {
          auto const [newPublicUserKey, sealedUserKey] = *extractedKeys;
          sealedKeys.push_back(sealedUserKey);
          user.userKey = newPublicUserKey;
        }
      }
    }
    catch (Errors::Exception const& err)
    {
      if (err.errorCode().category() == Tanker::Verif::ErrcCategory())
        TERROR("skipping invalid block {}: {}", serverEntry.hash(), err.what());
      else
        throw;
    }
  }
  return std::make_tuple(user, sealedKeys);
}

std::vector<Crypto::EncryptionKeyPair> recoverUserKeys(
    Crypto::EncryptionKeyPair const& devEncKP,
    gsl::span<SealedUserKey const> encryptedUserKeys)
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
      Crypto::sealDecrypt(selfEncKeyIt->sealedKey, devEncKP));

  // Second we decrypt the user keys before our device creation starting with
  // the current user key in reverse order.
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

std::tuple<Crypto::PublicSignatureKey,
           Users::User,
           std::vector<Crypto::EncryptionKeyPair>>
processUserEntries(DeviceKeys const& deviceKeys,
                   Trustchain::TrustchainId const& trustchainId,
                   gsl::span<Trustchain::ServerEntry const> entries)
{
  if (entries.size() == 0)
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "User's block list is empty");
  auto signatureKey = extractTrustchainSignature(trustchainId, entries[0]);
  auto [user, sealedKeys] = extractUserSealedKeys(
      deviceKeys, trustchainId, signatureKey, entries.subspan(1));
  auto userKeys = recoverUserKeys(deviceKeys.encryptionKeyPair, sealedKeys);
  return std::make_tuple(signatureKey, std::move(user), std::move(userKeys));
}
}
