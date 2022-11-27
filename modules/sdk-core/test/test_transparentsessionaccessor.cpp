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
  auto shareMock =
      [](auto const& _sess, auto const& _users, auto const& _groups) {};
  Accessor accessor(&store, shareMock);

  SECTION("it creates different sessions for different recipient lists")
  {
    auto sess1 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"1"}}));
    auto sess2 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"2"}}));
    CHECK(sess1.id != sess2.id);
  }

  SECTION("it reuses an existing session that has not expired")
  {
    auto sess1 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    auto sess2 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    CHECK(sess1.id == sess2.id);
  }

  SECTION("it ignores duplicates and sorting order")
  {
    auto sess1 =
        AWAIT(accessor.getOrCreateTransparentSession({}, {{"A"}, {"B"}}));
    auto sess2 = AWAIT(
        accessor.getOrCreateTransparentSession({}, {{"B"}, {"A"}, {"A"}}));
    CHECK(sess1.id == sess2.id);
  }

  SECTION("it creates a new session if the old one has expired")
  {
    auto sess1 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    AWAIT_VOID(store.put(sess1.recipientsHash, sess1.id, sess1.key, 0));

    auto sess2 = AWAIT(accessor.getOrCreateTransparentSession({}, {{"X"}}));
    CHECK(sess1.id != sess2.id);
  }
}
