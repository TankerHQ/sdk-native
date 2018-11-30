#include <Tanker/TrustchainPuller.hpp>

#include <Tanker/Actions/DeviceCreation.hpp>
#include <Tanker/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Actions/KeyPublishToUser.hpp>
#include <Tanker/Actions/UserKeyPair.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/DataStore/Connection.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain.hpp>
#include <Tanker/TrustchainVerifier.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UnverifiedEntry.hpp>

#include <mockaron/mockaron.hpp>
#include <mpark/variant.hpp>
#include <sqlpp11/transaction.h>
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
    Client* client,
    Crypto::PublicSignatureKey const& deviceSignatureKey,
    DeviceId const& deviceId,
    UserId const& userId)
  : _trustchain(trustchain),
    _verifier(verifier),
    _db(db),
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
          return blockToUnverifiedEntry(
              Serialization::deserialize<Block>(base64::decode(block)));
        });

    TC_AWAIT(_db->inTransaction([&]() -> tc::cotask<void> {
      std::set<Crypto::Hash> processed;
      if (_deviceId.is_null())
      {
        TINFO("No user id, processing our devices first");
        // process our blocks first or here's what'll happen!
        // if you receive:
        // - Device Creation
        // - Group Creation (with a key encrypted for my user key)
        // - My Device Creation (with my user key that I can decrypt)
        // If I process the Group Creation, I won't be able to decrypt it. More
        // generally, I can't process stuff if I don't have my user keys and
        // device id, so we do not process other blocks before we have those.
        for (auto const& unverifiedEntry : entries)
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
            }
          }
      }

      for (auto const& unverifiedEntry : entries)
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
    }));
    TINFO("Caught up");
  }
  catch (std::exception const& e)
  {
    TERROR("Failed to catch up: {}", e.what());
    throw;
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
}
}
