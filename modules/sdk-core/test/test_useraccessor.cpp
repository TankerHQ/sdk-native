#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/ITrustchainPuller.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "TrustchainBuilder.hpp"

#include <doctest.h>
#include <optional>
#include <tconcurrent/coroutine.hpp>
#include <trompeloeil.hpp>

using namespace Tanker;

namespace
{
class TrustchainPullerStub : public ITrustchainPuller
{
public:
  MAKE_MOCK2(scheduleCatchUp,
             tc::shared_future<void>(std::vector<Trustchain::UserId> const&,
                                     std::vector<Trustchain::GroupId> const&),
             override);
};
}

TEST_CASE("UserAccessor")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));
  Users::ContactStore contactStore(dbPtr.get());

  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice").user.asTankerUser();
  auto const bob = builder.makeUser3("bob").user.asTankerUser();
  auto const charlie = builder.makeUser3("charlie").user.asTankerUser();

  TrustchainPullerStub trustchainPuller;
  REQUIRE_CALL(trustchainPuller,
               scheduleCatchUp(trompeloeil::_, trompeloeil::_))
      .RETURN([](auto...) -> tc::shared_future<void> {
        return {tc::make_ready_future()};
      }());
  Users::UserAccessor userAccessor(
      alice.id, nullptr, &trustchainPuller, &contactStore);

  SUBCASE("it should return user ids it did not find")
  {
    std::vector<Trustchain::UserId> ids{bob.id, charlie.id};
    auto const result = AWAIT(userAccessor.pull(ids));
    CHECK_UNARY(result.found.empty());
    CHECK_EQ(result.notFound, ids);
  }

  SUBCASE("it should return found users")
  {
    AWAIT_VOID(contactStore.putUser(bob));
    AWAIT_VOID(contactStore.putUser(charlie));

    std::vector<Trustchain::UserId> ids{bob.id, charlie.id};
    auto const result = AWAIT(userAccessor.pull(ids));
    CHECK_UNARY(result.notFound.empty());
    CHECK_EQ(result.found, std::vector<Users::User>{bob, charlie});
  }
}
