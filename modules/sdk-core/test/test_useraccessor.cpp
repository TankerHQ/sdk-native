#include <Tanker/ContactStore.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>
#include <Tanker/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "TrustchainBuilder.hpp"

#include <doctest.h>
#include <mockaron/mockaron.hpp>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>
#include <trompeloeil.hpp>

using namespace Tanker;

namespace
{
class TrustchainPullerStub : public mockaron::mock_impl
{
public:
  TrustchainPullerStub()
  {
    MOCKARON_SET_IMPL(TrustchainPuller,
                      scheduleCatchUp,
                      [](auto...) -> tc::shared_future<void> {
                        return {tc::make_ready_future()};
                      });
  }
};
}

TEST_CASE("UserAccessor")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));
  ContactStore contactStore(dbPtr.get());

  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice").user.asTankerUser();
  auto const bob = builder.makeUser3("bob").user.asTankerUser();
  auto const charlie = builder.makeUser3("charlie").user.asTankerUser();

  mockaron::mock<TrustchainPuller, TrustchainPullerStub> trustchainPuller;
  UserAccessor userAccessor(
      alice.id, nullptr, &trustchainPuller.get(), &contactStore);

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
    CHECK_EQ(result.found, std::vector<User>{bob, charlie});
  }
}
