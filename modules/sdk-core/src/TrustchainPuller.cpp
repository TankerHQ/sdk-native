#include <Tanker/TrustchainPuller.hpp>

#include <Tanker/Block.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/TrustchainVerifier.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <mockaron/mockaron.hpp>
#include <tconcurrent/coroutine.hpp>

#include <algorithm>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

TLOG_CATEGORY(TrustchainPuller);

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
TrustchainPuller::TrustchainPuller(
    TrustchainStore* trustchain,
    TrustchainVerifier* verifier,
    DataStore::ADatabase* db,
    ContactStore* contactStore,
    UserKeyStore* userKeyStore,
    DeviceKeyStore* deviceKeyStore,
    Client* client,
    Crypto::PublicSignatureKey const& deviceSignatureKey,
    Trustchain::DeviceId const& deviceId,
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

void TrustchainPuller::setDeviceId(Trustchain::DeviceId const& deviceId)
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
    ServerEntry const& serverEntry)
{
  auto const entry = TC_AWAIT(_verifier->verify(serverEntry));
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
    std::vector<ServerEntry> entries;
    std::transform(
        std::begin(blocks),
        std::end(blocks),
        std::back_inserter(entries),
        [](auto const& block) {
          return blockToServerEntry(Serialization::deserialize<Block>(
              cppcodec::base64_rfc4648::decode(block)));
        });
    std::sort(
        entries.begin(), entries.end(), [](auto const& lhs, auto const& rhs) {
          return lhs.index() < rhs.index();
        });

    TC_AWAIT(_db->inTransaction([&]() -> tc::cotask<void> {
      std::set<Crypto::Hash> processed;
      if (_deviceId.is_null())
      {
        TINFO("No device id, processing our devices first");
        auto const initiallyProcessed = TC_AWAIT(doInitialProcess(entries));
        processed.insert(initiallyProcessed.begin(), initiallyProcessed.end());
      }
      {
        auto const processedClaims = TC_AWAIT(doClaimProcess(entries));
        processed.insert(processedClaims.begin(), processedClaims.end());
      }

      for (auto const& serverEntry : entries)
      {
        try
        {
          if (processed.count(serverEntry.hash()))
            continue;

          auto const existingEntry =
              TC_AWAIT(_db->findTrustchainEntry(serverEntry.hash()));
          if (!existingEntry)
          {
            TC_AWAIT(verifyAndAddEntry(serverEntry));
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

tc::cotask<std::set<Crypto::Hash>> TrustchainPuller::doInitialProcess(
    std::vector<ServerEntry> const& entries)
{
  std::set<Crypto::Hash> processed;
  std::vector<std::pair<Crypto::PublicEncryptionKey,
                        Crypto::SealedPrivateEncryptionKey>>
      encryptedUserKeys;
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
  for (auto const& serverEntry : entries)
  {
    try
    {
      if (serverEntry.action().get_if<TrustchainCreation>())
      {
        TC_AWAIT(verifyAndAddEntry(serverEntry));
        processed.insert(serverEntry.hash());
      }
      else if (auto const deviceCreation =
                   serverEntry.action().get_if<DeviceCreation>())
      {
        if (deviceCreation->userId() == _userId)
        {
          TC_AWAIT(verifyAndAddEntry(serverEntry));
          processed.insert(serverEntry.hash());
          if (auto dc3 = deviceCreation->get_if<DeviceCreation::v3>())
          {
            if (Trustchain::DeviceId{serverEntry.hash()} == _deviceId)
            {
              auto const lastPrivateEncryptionKey =
                  Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
                      dc3->sealedPrivateUserEncryptionKey(),
                      _deviceKeyStore->encryptionKeyPair());
              userEncryptionKeys.push_back(Crypto::EncryptionKeyPair{
                  dc3->publicUserEncryptionKey(), lastPrivateEncryptionKey});
            }
          }
          else
          {
            throw std::runtime_error(
                "assertion failed: self device must have a user key");
          }
        }
      }
      else if (auto const deviceRevocation =
                   serverEntry.action().get_if<DeviceRevocation>())
      {
        auto const userId = TC_AWAIT(
            _contactStore->findUserIdByDeviceId(deviceRevocation->deviceId()));
        if (userId == _userId)
        {
          TC_AWAIT(verifyAndAddEntry(serverEntry));
          processed.insert(serverEntry.hash());
          if (auto const deviceRevocation2 =
                  deviceRevocation->get_if<DeviceRevocation2>())
          {
            encryptedUserKeys.emplace_back(
                deviceRevocation2->previousPublicEncryptionKey(),
                deviceRevocation2->sealedKeyForPreviousUserKey());
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
  TC_RETURN(processed);
}

tc::cotask<std::set<Crypto::Hash>> TrustchainPuller::doClaimProcess(
    std::vector<ServerEntry> const& entries)
{
  std::set<Crypto::Hash> processed;
  // We must process our claims first because we might have group blocks later
  // that are addressed to our provisional identities
  for (auto const& serverEntry : entries)
  {
    try
    {
      if (serverEntry.action().get_if<ProvisionalIdentityClaim>())
      {
        TC_AWAIT(verifyAndAddEntry(serverEntry));
        processed.insert(serverEntry.hash());
      }
    }
    catch (Error::VerificationFailed const& err)
    {
      TERROR("Verification failed: {}", err.what());
    }
  }
  TC_RETURN(processed);
}

tc::cotask<void> TrustchainPuller::recoverUserKeys(
    std::vector<std::pair<Crypto::PublicEncryptionKey,
                          Crypto::SealedPrivateEncryptionKey>> const&
        encryptedUserKeys,
    std::vector<Crypto::EncryptionKeyPair>& userEncryptionKeys)
{
  auto const user = TC_AWAIT(_contactStore->findUser(_userId));
  for (auto userKeyIt = encryptedUserKeys.rbegin();
       userKeyIt != encryptedUserKeys.rend();
       ++userKeyIt)
  {
    auto const encryptionPrivateKey =
        Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
            userKeyIt->second, userEncryptionKeys.back());
    userEncryptionKeys.push_back(
        Crypto::EncryptionKeyPair{userKeyIt->first, encryptionPrivateKey});
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
  if (auto const deviceCreation = entry.action.get_if<DeviceCreation>())
  {
    if (deviceCreation->publicSignatureKey() == _devicePublicSignatureKey)
      TC_AWAIT(receivedThisDeviceId(Trustchain::DeviceId{entry.hash}));
    TC_AWAIT(deviceCreated(entry));
  }
  if (auto const keyPublish = entry.action.get_if<KeyPublish>())
  {
    if (auto const kpd = keyPublish->get_if<KeyPublish::ToDevice>())
    {
      if (kpd->recipient() == _deviceId)
        TC_AWAIT(receivedKeyToDevice(entry));
    }
    else
      TC_AWAIT(keyPublishReceived(entry));
  }
  if (entry.action.holdsAlternative<UserGroupCreation>() ||
      entry.action.holdsAlternative<UserGroupAddition>())
  {
    TC_AWAIT(userGroupActionReceived(entry));
  }
  else if (entry.action.holdsAlternative<DeviceRevocation>())
    TC_AWAIT(deviceRevoked(entry));
  else if (entry.action.holdsAlternative<ProvisionalIdentityClaim>())
    TC_AWAIT(provisionalIdentityClaimReceived(entry));
  else if (entry.action.holdsAlternative<TrustchainCreation>())
    TC_AWAIT(trustchainCreationReceived(entry));
}
}
