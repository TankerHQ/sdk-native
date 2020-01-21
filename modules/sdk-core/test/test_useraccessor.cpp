#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "TrustchainBuilder.hpp"
#include "UserRequesterStub.hpp"

#include <doctest.h>
#include <optional>
#include <tconcurrent/coroutine.hpp>
#include <trompeloeil.hpp>

using namespace Tanker;

TEST_CASE("UserAccessor")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));
  Users::ContactStore contactStore(dbPtr.get());

  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice").user.asTankerUser();
  auto const bob = builder.makeUser3("bob").user.asTankerUser();
  auto const charlie = builder.makeUser3("charlie").user.asTankerUser();

  UserRequesterStub requester;
  Users::UserAccessor userAccessor(
      builder.trustchainContext(), &requester, &contactStore);

  SUBCASE("it should return user ids it did not find")
  {
    REQUIRE_CALL(requester, getUsers(ANY(gsl::span<Trustchain::UserId const>)))
        .RETURN(makeCoTask(std::vector<Trustchain::ServerEntry>{}));
    std::vector<Trustchain::UserId> ids{bob.id(), charlie.id()};
    auto const result = AWAIT(userAccessor.pull(ids));
    CHECK_UNARY(result.found.empty());
    CHECK_EQ(result.notFound, ids);
  }

  SUBCASE("it should return found users")
  {
    AWAIT_VOID(contactStore.putUser(alice));
    AWAIT_VOID(contactStore.putUser(bob));
    AWAIT_VOID(contactStore.putUser(charlie));

    std::vector<Trustchain::UserId> ids{alice.id(), bob.id(), charlie.id()};

    REQUIRE_CALL(requester, getUsers(ids))
        .RETURN(makeCoTask(builder.entries()));
    auto result = AWAIT(userAccessor.pull(ids));
    CHECK_UNARY(result.notFound.empty());
    auto expectedUsers = std::vector<Users::User>{alice, bob, charlie};

    std::sort(result.found.begin(), result.found.end());
    std::sort(expectedUsers.begin(), expectedUsers.end());
    CHECK_EQ(result.found, expectedUsers);
  }
}
