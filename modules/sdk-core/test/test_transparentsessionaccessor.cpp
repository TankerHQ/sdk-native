#include <Tanker/TransparentSession/Accessor.hpp>
#include <Tanker/TransparentSession/Store.hpp>

#include <Tanker/DataStore/Sqlite/Backend.hpp>

#include <Helpers/Await.hpp>

#include <catch2/catch.hpp>

using namespace Tanker;
using namespace Tanker::Crypto;
using namespace Tanker::TransparentSession;

TEST_CASE("TransparentSessionAccessor")
{
  auto db = DataStore::SqliteBackend().open(DataStore::MemoryPath,
                                            DataStore::MemoryPath);
  Store store({}, db.get());
  Accessor accessor(&store);

  SECTION("it creates different sessions for different recipient lists")
  {
    auto sess1 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"1"}}));
    auto sess2 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"2"}}));
    CHECK(sess1.isNew);
    CHECK(sess2.isNew);
    CHECK(sess1.sessionId != sess2.sessionId);
  }

  SECTION("it reuses an existing session that has not expired")
  {
    auto sess1 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    auto sess2 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    CHECK(sess1.isNew);
    CHECK(!sess2.isNew);
    CHECK(sess1.sessionId == sess2.sessionId);
  }

  SECTION("it creates a new session if the old one has expired")
  {
    auto sess1 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    CHECK(sess1.isNew);

    auto hash = Store::hashRecipients({}, {{"X"}});
    CHECK(AWAIT(store.get(hash)).has_value());
    AWAIT_VOID(store.put(hash, sess1.sessionId, sess1.sessionKey, 0));

    auto sess2 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    CHECK(sess2.isNew);
    CHECK(sess1.sessionId != sess2.sessionId);
  }
}
