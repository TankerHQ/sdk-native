#include <Tanker/TransparentSession/Store.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>
#include <Tanker/Utils.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;
using namespace Tanker::Crypto;
using namespace Tanker::TransparentSession;

namespace Tanker
{
// Do not let doctest pickup variant2's operator<<
inline std::ostream& operator<<(std::ostream& os,
                                TransparentSessionData const&) = delete;
}

TEST_CASE("TransparentSessionStore")
{
  auto db = DataStore::SqliteBackend().open(DataStore::MemoryPath,
                                            DataStore::MemoryPath);

  Store store({}, db.get());

  auto const firstSessionId = make<SimpleResourceId>("sess id 1");
  auto const firstSessionKey = make<SymmetricKey>("sess key 1");

  auto const secondSessionId = make<SimpleResourceId>("sess id 2");
  auto const secondSessionKey = make<SymmetricKey>("sess key 2");

  SECTION("it should not find a non-existent transparent session")
  {
    auto const unknownRecipients = make<Hash>("nonexistent");
    CHECK(AWAIT(store.get(unknownRecipients)) == std::nullopt);
  }

  SECTION("it should find a transparent session that was inserted")
  {
    auto const recipients = make<Hash>("Nicolas Bourbaki");

    AWAIT_VOID(store.put(recipients, firstSessionId, firstSessionKey, 42));
    auto const result = AWAIT(store.get(recipients)).value();
    CHECK(result.creationTimestamp == 42);
    CHECK(result.sessionId == firstSessionId);
    CHECK(result.sessionKey == firstSessionKey);
  }

  SECTION("it should insert sessions with a current timestamp by default")
  {
    auto const recipients = make<Hash>("Hungarian martians");

    AWAIT_VOID(store.put(recipients, firstSessionId, firstSessionKey));
    auto const result = AWAIT(store.get(recipients)).value();
    CHECK(secondsSinceEpoch() - result.creationTimestamp < 5);
  }

  SECTION("it should overwrite a session")
  {
    auto const recipients = make<Hash>("Solvay");

    AWAIT_VOID(store.put(recipients, firstSessionId, firstSessionKey, 11));
    AWAIT_VOID(store.put(recipients, secondSessionId, secondSessionKey, 22));
    auto const result = AWAIT(store.get(recipients)).value();

    CHECK(result.creationTimestamp == 22);
    CHECK(result.sessionId == secondSessionId);
    CHECK(result.sessionKey == secondSessionKey);
  }

  SECTION("Generates the same recipient hashes regardless of user order")
  {
    auto user1 = SPublicIdentity("u1"), user2 = SPublicIdentity("u2");
    auto hash1 = Store::hashRecipients({user1, user2}, {});
    auto hash2 = Store::hashRecipients({user2, user1}, {});
    CHECK(hash1 == hash2);
  }

  SECTION("Generates the same recipient hashes regardless of group order")
  {
    auto group1 = SGroupId("g1"), group2 = SGroupId("g2");
    auto hash1 = Store::hashRecipients({}, {group1, group2});
    auto hash2 = Store::hashRecipients({}, {group2, group1});
    CHECK(hash1 == hash2);
  }

  SECTION("Generates different hashes when given a user ID vs a group ID")
  {
    auto user = SPublicIdentity("Same string!");
    auto group = SGroupId("Same string!");
    auto hash1 = Store::hashRecipients({user}, {});
    auto hash2 = Store::hashRecipients({}, {group});
    CHECK(hash1 != hash2);
  }
}
