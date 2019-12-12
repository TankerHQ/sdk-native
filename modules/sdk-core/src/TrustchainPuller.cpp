#include <Tanker/TrustchainPuller.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/TrustchainVerifier.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Verif/Errors/ErrcCategory.hpp>

#include <tconcurrent/coroutine.hpp>

#include <algorithm>
#include <functional>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

TLOG_CATEGORY(TrustchainPuller);

using namespace std::string_literals;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
TrustchainPuller::TrustchainPuller(TrustchainStore* trustchain,
                                   TrustchainVerifier* verifier,
                                   DataStore::ADatabase* db,
                                   Users::LocalUser* localUser,
                                   Users::ContactStore* contactStore,
                                   Client* client)
  : _trustchain(trustchain),
    _verifier(verifier),
    _db(db),
    _localUser(localUser),
    _contactStore(contactStore),
    _client(client),
    _pullJob([this] {
      return tc::async_resumable(
          [this]() -> tc::cotask<void> { TC_AWAIT(catchUp()); });
    })
{
}

tc::shared_future<void> TrustchainPuller::scheduleCatchUp(
    std::vector<UserId> const& extraUsers,
    std::vector<GroupId> const& extraGroups)
{
  _extraUsers.insert(_extraUsers.end(), extraUsers.begin(), extraUsers.end());
  _extraGroups.insert(
      _extraGroups.end(), extraGroups.begin(), extraGroups.end());
  return _pullJob.trigger();
}

tc::cotask<void> TrustchainPuller::verifyAndAddEntry(
    ServerEntry const& serverEntry)
{
  // we don't handle group group blocks here anymore
  if (serverEntry.action().holds_alternative<UserGroupCreation>() ||
      serverEntry.action().holds_alternative<UserGroupAddition>())
  {
    TERROR(
        "The server has sent us group blocks even though we didn't ask for "
        "them");
    TC_RETURN();
  }

  auto const existingEntry =
      TC_AWAIT(_db->findTrustchainEntry(serverEntry.hash()));
  if (!existingEntry)
  {
    auto const entry = TC_AWAIT(_verifier->verify(serverEntry));
    TC_AWAIT(_trustchain->addEntry(entry));
    TC_AWAIT(triggerSignals(entry));
  }
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
    auto entries = fromBlocksToServerEntries(blocks);
    std::sort(
        entries.begin(), entries.end(), [](auto const& lhs, auto const& rhs) {
          return lhs.index() < rhs.index();
        });

    TC_AWAIT(_db->inTransaction([&]() -> tc::cotask<void> {
      std::set<Crypto::Hash> processed;
      if (_localUser->deviceId().is_null())
      {
        TINFO("No device id, processing our devices first");
        auto const initiallyProcessed = TC_AWAIT(doInitialProcess(entries));
        processed.insert(initiallyProcessed.begin(), initiallyProcessed.end());
      }

      for (auto const& serverEntry : entries)
      {
        try
        {
          if (processed.count(serverEntry.hash()))
            continue;

          TC_AWAIT(verifyAndAddEntry(serverEntry));
        }
        catch (Errors::Exception const& err)
        {
          if (err.errorCode().category() == Verif::ErrcCategory())
          {
            TERROR("skipping invalid block {}: {}",
                   serverEntry.hash(),
                   err.what());
          }
          else
            throw;
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
  catch (...)
  {
    TERROR("Failed to catch up: unknown error");
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
  // - InternalGroup Creation (with a key encrypted for my user key)
  // - My Device Creation (with my user key that I can decrypt)
  // If I process the InternalGroup Creation, I won't be able to decrypt it.
  // More generally, I can't process stuff if I don't have my user keys and
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
        if (deviceCreation->userId() == _localUser->userId())
        {
          TC_AWAIT(verifyAndAddEntry(serverEntry));
          processed.insert(serverEntry.hash());
          if (auto dc3 = deviceCreation->get_if<DeviceCreation::v3>())
          {
            if (Trustchain::DeviceId{serverEntry.hash()} ==
                _localUser->deviceId())
            {
              auto const lastPrivateEncryptionKey = Crypto::sealDecrypt(
                  dc3->sealedPrivateUserEncryptionKey(),
                  _localUser->deviceKeys().encryptionKeyPair);
              userEncryptionKeys.push_back(Crypto::EncryptionKeyPair{
                  dc3->publicUserEncryptionKey(), lastPrivateEncryptionKey});
            }
          }
          else
            throw Errors::AssertionError("self device must have a user key");
        }
      }
      else if (auto const deviceRevocation =
                   serverEntry.action().get_if<DeviceRevocation>())
      {
        auto const userId = TC_AWAIT(
            _contactStore->findUserIdByDeviceId(deviceRevocation->deviceId()));
        if (userId == _localUser->userId())
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
    catch (Errors::Exception const& err)
    {
      if (err.errorCode().category() == Verif::ErrcCategory())
      {
        TERROR("skipping invalid block {}: {}", serverEntry.hash(), err.what());
      }
      else
        throw;
    }
  }
  TC_AWAIT(recoverUserKeys(encryptedUserKeys, userEncryptionKeys));
  TC_RETURN(processed);
}

tc::cotask<void> TrustchainPuller::recoverUserKeys(
    std::vector<std::pair<Crypto::PublicEncryptionKey,
                          Crypto::SealedPrivateEncryptionKey>> const&
        encryptedUserKeys,
    std::vector<Crypto::EncryptionKeyPair>& userEncryptionKeys)
{
  auto const user = TC_AWAIT(_contactStore->findUser(_localUser->userId()));
  for (auto userKeyIt = encryptedUserKeys.rbegin();
       userKeyIt != encryptedUserKeys.rend();
       ++userKeyIt)
  {
    auto const encryptionPrivateKey =
        Crypto::sealDecrypt(userKeyIt->second, userEncryptionKeys.back());
    userEncryptionKeys.push_back(
        Crypto::EncryptionKeyPair{userKeyIt->first, encryptionPrivateKey});
  }
  if (userEncryptionKeys.empty())
    throw Errors::AssertionError("self device must have a user key");
  for (auto encryptionKeyPairIt = userEncryptionKeys.rbegin();
       encryptionKeyPairIt != userEncryptionKeys.rend();
       ++encryptionKeyPairIt)
  {
    TC_AWAIT(_localUser->insertUserKey(*encryptionKeyPairIt));
  }
}

tc::cotask<void> TrustchainPuller::triggerSignals(Entry const& entry)
{
  if (auto const deviceCreation = entry.action.get_if<DeviceCreation>())
  {
    if (deviceCreation->publicSignatureKey() ==
        _localUser->deviceKeys().signatureKeyPair.publicKey)
    {
      TC_AWAIT(_localUser->setDeviceId(Trustchain::DeviceId{entry.hash}));
      TC_AWAIT(receivedThisDeviceId(Trustchain::DeviceId{entry.hash}));
    }
    TC_AWAIT(deviceCreated(entry));
  }
  else if (entry.action.holds_alternative<DeviceRevocation>())
    TC_AWAIT(deviceRevoked(entry));
  else if (entry.action.holds_alternative<TrustchainCreation>())
    TC_AWAIT(trustchainCreationReceived(entry));
}
}
