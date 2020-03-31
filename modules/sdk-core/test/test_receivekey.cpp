#include <Tanker/ReceiveKey.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/ResourceKeys/Store.hpp>

#include "GroupAccessorMock.hpp"
#include "LocalUserAccessorMock.hpp"
#include "ProvisionalUsersAccessorMock.hpp"
#include "TestVerifier.hpp"
#include "TrustchainGenerator.hpp"

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/MakeCoTask.hpp>

#include <trompeloeil.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;

namespace
{
auto makeEntry = [](Trustchain::ClientEntry const& clientEntry) {
  return toVerifiedEntry(Test::Generator::makeEntryList({clientEntry}).front());
};
}

TEST_CASE("decryptAndStoreKey")
{
  Test::Generator generator;
  auto const receiver = generator.makeUser("receiver");
  auto const sender = generator.makeUser("sender");
  auto const& senderDevice = sender.devices().front();

  auto const resource = Test::Resource();

  auto const db = AWAIT(DataStore::createDatabase(":memory:"));
  ResourceKeys::Store resourceKeyStore(db.get());
  GroupAccessorMock receiverGroupAccessor;
  LocalUserAccessorMock receiverLocalUserAccessor;
  ProvisionalUsersAccessorMock receiverProvisionalUsersAccessor;

  SUBCASE("should process a key publish to user entry")
  {
    auto const keyPublishEntry =
        makeEntry(generator.shareWith(senderDevice, receiver, resource));

    REQUIRE_CALL(receiverLocalUserAccessor,
                 pullUserKeyPair(receiver.userKeys().back().publicKey))
        .RETURN(makeCoTask(std::make_optional(receiver.userKeys().back())));

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        receiverLocalUserAccessor,
        receiverGroupAccessor,
        receiverProvisionalUsersAccessor,
        keyPublishEntry.action.get<KeyPublish>()));
  }

  SUBCASE("should process a key publish to group entry")
  {
    auto const group = receiver.makeGroup();
    auto const keyPublishEntry =
        makeEntry(generator.shareWith(senderDevice, group, resource));

    REQUIRE_CALL(receiverGroupAccessor, getEncryptionKeyPair(trompeloeil::_))
        .LR_RETURN(makeCoTask(std::make_optional(group.currentEncKp())));

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        receiverLocalUserAccessor,
        receiverGroupAccessor,
        receiverProvisionalUsersAccessor,
        keyPublishEntry.action.get<KeyPublish>()));
  }

  SUBCASE("should process a key publish to provisional user")
  {
    auto const provisionalUser = generator.makeProvisionalUser("bob@gmail.com");

    auto const keyPublishEntry =
        makeEntry(generator.shareWith(senderDevice, provisionalUser, resource));

    REQUIRE_CALL(
        receiverProvisionalUsersAccessor,
        pullEncryptionKeys(provisionalUser.appSignatureKeyPair().publicKey,
                           provisionalUser.tankerSignatureKeyPair().publicKey))
        .LR_RETURN(makeCoTask(
            std::make_optional<ProvisionalUserKeys>(provisionalUser)));

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        receiverLocalUserAccessor,
        receiverGroupAccessor,
        receiverProvisionalUsersAccessor,
        keyPublishEntry.action.get<KeyPublish>()));
  }
  CHECK_EQ(AWAIT(resourceKeyStore.getKey(resource.id())), resource.key());
}
