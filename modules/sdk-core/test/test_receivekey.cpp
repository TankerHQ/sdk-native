#include <Tanker/ReceiveKey.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Users/ContactStore.hpp>

#include "FakeProvisionalUsersAccessor.hpp"
#include "GroupAccessorMock.hpp"
#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/MakeCoTask.hpp>

#include <trompeloeil.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("decryptAndStoreKey")
{
  TrustchainBuilder builder;
  builder.makeUser3("receiver");
  builder.makeUser3("sender");

  auto const receiver = *builder.findUser("receiver");

  auto const sender = *builder.findUser("sender");
  auto const senderDevice = sender.devices.front();

  auto const resourceMac = make<Trustchain::ResourceId>("resource resourceId");
  auto const resourceKey = make<Crypto::SymmetricKey>("the KEY");

  SUBCASE("should process a key publish to user entry")
  {
    auto const keyPublishEntry =
        builder.shareToUser(senderDevice, receiver, resourceMac, resourceKey);
    auto const keyPublishToUserEntry = toVerifiedEntry(keyPublishEntry);

    auto const db = AWAIT(DataStore::createDatabase(":memory:"));
    auto const receiverKeyStore = builder.makeLocalUser(receiver, db.get());
    GroupAccessorMock receiverGroupAccessor;
    ProvisionalUserKeysStore const receiverProvisionalUserKeysStore(db.get());
    auto const receiverProvisionalUsersAccessor =
        std::make_unique<FakeProvisionalUsersAccessor>(
            receiverProvisionalUserKeysStore);
    ResourceKeyStore resourceKeyStore(db.get());

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        *receiverKeyStore,
        receiverGroupAccessor,
        *receiverProvisionalUsersAccessor,
        keyPublishToUserEntry.action.get<KeyPublish>()));

    CHECK(AWAIT(resourceKeyStore.getKey(resourceMac)) == resourceKey);
  }

  SUBCASE("should process a key publish to group entry")
  {
    auto const group = builder.makeGroup(receiver.devices[0], {receiver});

    auto const keyPublishEntry = builder.shareToUserGroup(
        senderDevice, group.group, resourceMac, resourceKey);
    auto const keyPublishToUserGroupEntry = toVerifiedEntry(keyPublishEntry);

    auto const db = AWAIT(DataStore::createDatabase(":memory:"));
    auto const receiverKeyStore = builder.makeLocalUser(receiver, db.get());
    GroupAccessorMock receiverGroupAccessor;
    REQUIRE_CALL(receiverGroupAccessor, getEncryptionKeyPair(trompeloeil::_))
        .LR_RETURN(makeCoTask(
            std::make_optional(group.group.tankerGroup.encryptionKeyPair)));
    ProvisionalUserKeysStore const receiverProvisionalUserKeysStore(db.get());
    auto const receiverProvisionalUsersAccessor =
        std::make_unique<FakeProvisionalUsersAccessor>(
            receiverProvisionalUserKeysStore);
    ResourceKeyStore resourceKeyStore(db.get());

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        *receiverKeyStore,
        receiverGroupAccessor,
        *receiverProvisionalUsersAccessor,
        keyPublishToUserGroupEntry.action.get<KeyPublish>()));

    CHECK(AWAIT(resourceKeyStore.getKey(resourceMac)) == resourceKey);
  }

  SUBCASE("should process a key publish to provisional user")
  {
    auto const provisionalUser = builder.makeProvisionalUser("bob@gmail.com");

    auto const keyPublishEntry =
        builder.shareToProvisionalUser(senderDevice,
                                       provisionalUser.publicProvisionalUser,
                                       resourceMac,
                                       resourceKey);
    auto const keyPublishToProvisionalUserEntry =
        toVerifiedEntry(keyPublishEntry);

    auto const db = AWAIT(DataStore::createDatabase(":memory:"));
    auto const receiverKeyStore = builder.makeLocalUser(receiver, db.get());
    GroupAccessorMock receiverGroupAccessor;
    auto const receiverProvisionalUserKeysStore =
        builder.makeProvisionalUserKeysStoreWith({provisionalUser}, db.get());
    auto const receiverProvisionalUsersAccessor =
        std::make_unique<FakeProvisionalUsersAccessor>(
            *receiverProvisionalUserKeysStore);
    ResourceKeyStore resourceKeyStore(db.get());

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        *receiverKeyStore,
        receiverGroupAccessor,
        *receiverProvisionalUsersAccessor,
        keyPublishToProvisionalUserEntry.action.get<KeyPublish>()));

    CHECK(AWAIT(resourceKeyStore.getKey(resourceMac)) == resourceKey);
  }
}
