#include <Tanker/Groups/Store.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Database.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <doctest/doctest.h>

using namespace Tanker;
using Tanker::Trustchain::GroupId;

TEST_CASE("GroupKeyStore")
{
  auto db = AWAIT(DataStore::createDatabase(":memory:"));

  Groups::Store groupStore(&db);

  auto const groupId = make<GroupId>("group id");
  auto const groupKey = Crypto::makeEncryptionKeyPair();

  SUBCASE("it should not find a non-existent group key")
  {
    auto const nonexistentGroupKey =
        make<Crypto::PublicEncryptionKey>("nonexistent");

    CHECK_EQ(
        AWAIT(groupStore.findKeyByPublicEncryptionKey(nonexistentGroupKey)),
        std::nullopt);
  }

  SUBCASE("it should find a group key that was inserted")
  {
    AWAIT_VOID(groupStore.putKeys(groupId, {groupKey}));
    CHECK_EQ(AWAIT(groupStore.findKeyByPublicEncryptionKey(groupKey.publicKey))
                 .value(),
             groupKey);
  }
}
