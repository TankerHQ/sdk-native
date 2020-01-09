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
                                   Users::LocalUser const* localUser,
                                   TrustchainVerifier* verifier,
                                   DataStore::ADatabase* db,
                                   Client* client)
  : _trustchain(trustchain),
    _localUser(localUser),
    _verifier(verifier),
    _db(db),
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
      for (auto const& serverEntry : entries)
        try
        {
          // FIXME
          if (auto const dc = serverEntry.action().get_if<DeviceCreation>();
              dc && dc->userId() == _localUser->userId())
            continue;
          else if (auto const dr =
                       serverEntry.action().get_if<DeviceRevocation>())
            if (auto const dr2 = dr->get_if<DeviceRevocation2>();
                dr2 &&
                TC_AWAIT(_localUser->findKeyPair(dr2->publicEncryptionKey())))
              continue;
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

tc::cotask<void> TrustchainPuller::triggerSignals(Entry const& entry)
{
  if (auto const deviceCreation = entry.action.get_if<DeviceCreation>())
    TC_AWAIT(deviceCreated(entry));
  else if (entry.action.holds_alternative<DeviceRevocation>())
    TC_AWAIT(deviceRevoked(entry));
}
}
