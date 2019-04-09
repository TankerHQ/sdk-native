#include <Tanker/TrustchainPuller.hpp>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Actions/KeyPublishToUser.hpp>
#include <Tanker/Actions/UserKeyPair.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain.hpp>
#include <Tanker/TrustchainVerifier.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UnverifiedEntry.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <mockaron/mockaron.hpp>
#include <mpark/variant.hpp>
#include <tconcurrent/coroutine.hpp>

#include <algorithm>
#include <functional>
#include <iterator>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

TLOG_CATEGORY(TrustchainPuller);

namespace Tanker
{
TrustchainPuller::TrustchainPuller(
    Trustchain* trustchain,
    TrustchainVerifier* verifier,
    DataStore::ADatabase* db,
    ContactStore* contactStore,
    UserKeyStore* userKeyStore,
    DeviceKeyStore* deviceKeyStore,
    Client* client,
    Crypto::PublicSignatureKey const& deviceSignatureKey,
    DeviceId const& deviceId,
    UserId const& userId)
  : _trustchain(trustchain),
    _verifier(verifier),
    _db(db),
    _contactStore(contactStore),
    _userKeyStore(userKeyStore),
    _deviceKeyStore(deviceKeyStore),
    _client(client),
    _devicePublicSignatureKey(deviceSignatureKey),
    _deviceId(deviceId),
    _userId(userId),
    _pullJob([this] {
      return tc::async_resumable(
          [this]() -> tc::cotask<void> { TC_AWAIT(catchUp()); });
    })
{
}

void TrustchainPuller::setDeviceId(DeviceId const& deviceId)
{
  _deviceId = deviceId;
}

tc::shared_future<void> TrustchainPuller::scheduleCatchUp(
    std::vector<UserId> const& extraUsers,
    std::vector<GroupId> const& extraGroups)
{
  MOCKARON_HOOK(TrustchainPuller, scheduleCatchUp, extraUsers, extraGroups);

  _extraUsers.insert(_extraUsers.end(), extraUsers.begin(), extraUsers.end());
  _extraGroups.insert(
      _extraGroups.end(), extraGroups.begin(), extraGroups.end());
  return _pullJob.trigger_success();
}

tc::cotask<void> TrustchainPuller::verifyAndAddEntry(
    UnverifiedEntry const& unverifiedEntry)
{
  auto const entry = TC_AWAIT(_verifier->verify(unverifiedEntry));
  TC_AWAIT(_trustchain->addEntry(entry));
  TC_AWAIT(triggerSignals(entry));
}

tc::cotask<void> TrustchainPuller::catchUp()
{
  try
  {
    TINFO("Catching up");
    auto const extraUsers = std::exchange(_extraUsers, {});
    auto const extraGroups = std::exchange(_extraGroups, {});
    auto const blocks = TC_AWAIT(_client->getBlocks(
        TC_AWAIT(_trustchain->getLastIndex()), extraUsers, extraGroups));
    std::vector<UnverifiedEntry> entries;
    std::transform(
        std::begin(blocks),
        std::end(blocks),
        std::back_inserter(entries),
        [](auto const& block) {
          return blockToUnverifiedEntry(Serialization::deserialize<Block>(
              cppcodec::base64_rfc4648::decode(block)));
        });

    TC_AWAIT(_db->inTransaction([&]() -> tc::cotask<void> {
      std::set<Crypto::Hash> processed;
      if (_deviceId.is_null())
      {
        TINFO("No device id, processing our devices first");
        std::vector<UserKeyPair> encryptedUserKeys;
        std::vector<Crypto::EncryptionKeyPair> userEncryptionKeys;
        // process our blocks first or here's what'll happen!
        // if you receive:
        // - Device Creation
        // - Group Creation (with a key encrypted for my user key)
        // - My Device Creation (with my user key that I can decrypt)
        // If I process the Group Creation, I won't be able to decrypt it. More
        // generally, I can't process stuff if I don't have my user keys and
        // device id, so we do not process other blocks before we have those.
        // - Device revocation
        // I need to get all the previous userKeys in order of creation to fill
        // the userKeyStore. To do that we have to store all previous sealed
        // private user keys and decrypt them one by one in reverse order. If we
        // don't do that It will not be possible for the new device to decrypt
        // old ressources.
        for (auto const& unverifiedEntry : entries)
        {
          try
          {
            if (mpark::get_if<TrustchainCreation>(
                    &unverifiedEntry.action.variant()))
            {
              TC_AWAIT(verifyAndAddEntry(unverifiedEntry));
              processed.insert(unverifiedEntry.hash);
            }
            else if (auto const deviceCreation = mpark::get_if<DeviceCreation>(
                         &unverifiedEntry.action.variant()))
            {
              if (deviceCreation->userId() == _userId)
              {
                TC_AWAIT(verifyAndAddEntry(unverifiedEntry));
                processed.insert(unverifiedEntry.hash);
                if (!deviceCreation->userKeyPair().has_value())
                {
                  throw std::runtime_error(
                      "assertion failed: self device must have a user key");
                }
                if (DeviceId{unverifiedEntry.hash} == _deviceId)
                {
                  auto const lastPrivateEncryptionKey =
                      Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
                          deviceCreation->userKeyPair()
                              ->encryptedPrivateEncryptionKey,
                          _deviceKeyStore->encryptionKeyPair());

                  userEncryptionKeys.push_back(Crypto::EncryptionKeyPair{
                      deviceCreation->userKeyPair()->publicEncryptionKey,
                      lastPrivateEncryptionKey});
                }
              }
            }
            else if (auto const deviceRevocation =
                         mpark::get_if<DeviceRevocation>(
                             &unverifiedEntry.action.variant()))
            {
              auto const userId = TC_AWAIT(_contactStore->findUserIdByDeviceId(
                  deviceRevocation->deviceId()));
              if (userId == _userId)
              {
                TC_AWAIT(verifyAndAddEntry(unverifiedEntry));
                processed.insert(unverifiedEntry.hash);
                if (auto const deviceRevocation2 =
                        mpark::get_if<DeviceRevocation2>(
                            &deviceRevocation->variant()))
                {
                  encryptedUserKeys.push_back(UserKeyPair{
                      deviceRevocation2->previousPublicEncryptionKey,
                      deviceRevocation2->encryptedKeyForPreviousUserKey});
                }
              }
            }
          }
          catch (Error::VerificationFailed const& err)
          {
            TERROR("Verification failed: {}", err.what());
          }
        }
        TC_AWAIT(recoverUserKeys(encryptedUserKeys, userEncryptionKeys));
      }

      for (auto const& unverifiedEntry : entries)
      {
        try
        {
          if (processed.count(unverifiedEntry.hash))
            continue;

          auto const existingEntry =
              TC_AWAIT(_db->findTrustchainEntry(unverifiedEntry.hash));
          if (!existingEntry)
          {
            TC_AWAIT(verifyAndAddEntry(unverifiedEntry));
          }
        }
        catch (Error::VerificationFailed const& err)
        {
          TERROR("Verification failed: {}", err.what());
        }
      }
    }));
    TINFO("Caught up");
  }
  catch (std::exception const& e)
  {
    TERROR("Failed to catch up: {}", e.what());
    throw;
  }
}

tc::cotask<void> TrustchainPuller::recoverUserKeys(
    std::vector<UserKeyPair> const& encryptedUserKeys,
    std::vector<Crypto::EncryptionKeyPair>& userEncryptionKeys)
{
  auto const user = TC_AWAIT(_contactStore->findUser(_userId));
  for (auto userKeyIt = encryptedUserKeys.rbegin();
       userKeyIt != encryptedUserKeys.rend();
       ++userKeyIt)
  {
    auto const encryptionPrivateKey =
        Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
            userKeyIt->encryptedPrivateEncryptionKey.base(),
            userEncryptionKeys.back());
    userEncryptionKeys.push_back(Crypto::EncryptionKeyPair{
        userKeyIt->publicEncryptionKey, encryptionPrivateKey});
  }
  if (userEncryptionKeys.empty())
  {
    throw std::runtime_error(
        "assertion failed: self device must have a user key");
  }
  for (auto encryptionKeyPairIt = userEncryptionKeys.rbegin();
       encryptionKeyPairIt != userEncryptionKeys.rend();
       ++encryptionKeyPairIt)
  {
    TC_AWAIT(_userKeyStore->putPrivateKey(encryptionKeyPairIt->publicKey,
                                          encryptionKeyPairIt->privateKey));
  }
}

tc::cotask<void> TrustchainPuller::triggerSignals(Entry const& entry)
{
  if (auto const deviceCreation =
          mpark::get_if<DeviceCreation>(&entry.action.variant()))
  {
    if (deviceCreation->publicSignatureKey() == _devicePublicSignatureKey)
      TC_AWAIT(receivedThisDeviceId(DeviceId{entry.hash}));
    TC_AWAIT(deviceCreated(entry));
  }
  // Legacy key publishes
  if (auto const keyPublish =
          mpark::get_if<KeyPublishToDevice>(&entry.action.variant()))
  {
    if (keyPublish->recipient == _deviceId)
      TC_AWAIT(receivedKeyToDevice(entry));
  }
  // current key publishes
  if (mpark::holds_alternative<KeyPublishToUser>(entry.action.variant()))
    receivedKeyToUser(entry);
  if (mpark::holds_alternative<KeyPublishToUserGroup>(entry.action.variant()))
    receivedKeyToUserGroup(entry);
  if (mpark::holds_alternative<UserGroupCreation>(entry.action.variant()) ||
      mpark::holds_alternative<UserGroupAddition>(entry.action.variant()))
    TC_AWAIT(userGroupActionReceived(entry));
  if (mpark::holds_alternative<DeviceRevocation>(entry.action.variant()))
    TC_AWAIT(deviceRevoked(entry));
}
}
