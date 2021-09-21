#include <Tanker/ReceiveKey.hpp>

#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>
#include <Tanker/ResourceKeys/Store.hpp>

#include "GroupAccessorMock.hpp"
#include "LocalUserAccessorMock.hpp"
#include "ProvisionalUsersAccessorMock.hpp"
#include "TrustchainGenerator.hpp"

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/MakeCoTask.hpp>

#include <trompeloeil.hpp>

#include <doctest/doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("decryptAndStoreKey")
{
  Test::Generator generator;
  auto const receiver = generator.makeUser("receiver");
  auto const sender = generator.makeUser("sender");
  auto const& senderDevice = sender.devices().front();

  auto const resource = Test::Resource();

  auto db = DataStore::SqliteBackend().open(":memory:", ":memory:");

  ResourceKeys::Store resourceKeyStore({}, db.get());
  GroupAccessorMock receiverGroupAccessor;
  LocalUserAccessorMock receiverLocalUserAccessor;
  ProvisionalUsersAccessorMock receiverProvisionalUsersAccessor;

  SUBCASE("should process a key publish to user action")
  {
    auto const keyPublishEntry =
        generator.shareWith(senderDevice, receiver, resource);

    REQUIRE_CALL(receiverLocalUserAccessor,
                 pullUserKeyPair(receiver.userKeys().back().publicKey))
        .RETURN(makeCoTask(std::make_optional(receiver.userKeys().back())));

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(resourceKeyStore,
                                              receiverLocalUserAccessor,
                                              receiverGroupAccessor,
                                              receiverProvisionalUsersAccessor,
                                              keyPublishEntry));
  }

  SUBCASE("should process a key publish to group action")
  {
    auto const group = receiver.makeGroup();
    auto const keyPublishEntry =
        generator.shareWith(senderDevice, group, resource);

    REQUIRE_CALL(receiverGroupAccessor, getEncryptionKeyPair(trompeloeil::_))
        .LR_RETURN(makeCoTask(std::make_optional(group.currentEncKp())));

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(resourceKeyStore,
                                              receiverLocalUserAccessor,
                                              receiverGroupAccessor,
                                              receiverProvisionalUsersAccessor,
                                              keyPublishEntry));
  }

  SUBCASE("should process a key publish to provisional user")
  {
    auto const provisionalUser = generator.makeProvisionalUser("bob@gmail.com");

    auto const keyPublishEntry =
        generator.shareWith(senderDevice, provisionalUser, resource);

    REQUIRE_CALL(
        receiverProvisionalUsersAccessor,
        pullEncryptionKeys(provisionalUser.appSignatureKeyPair().publicKey,
                           provisionalUser.tankerSignatureKeyPair().publicKey))
        .LR_RETURN(makeCoTask(
            std::make_optional<ProvisionalUserKeys>(provisionalUser)));

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(resourceKeyStore,
                                              receiverLocalUserAccessor,
                                              receiverGroupAccessor,
                                              receiverProvisionalUsersAccessor,
                                              keyPublishEntry));
  }
  CHECK_EQ(AWAIT(resourceKeyStore.getKey(resource.id())), resource.key());
}
