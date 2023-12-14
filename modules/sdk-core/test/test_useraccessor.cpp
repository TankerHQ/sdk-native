#include <Tanker/Share.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/User.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "TrustchainGenerator.hpp"
#include "UserRequesterStub.hpp"

#include <catch2/catch_test_macros.hpp>
#include <trompeloeil.hpp>

using namespace Tanker;

TEST_CASE("UserAccessor")
{
  Test::Generator generator;
  auto const alice = generator.makeUser("alice");
  auto const bob = generator.makeUser("bob");
  auto const charlie = generator.makeUser("charlie");

  UserRequesterStub requester;
  Users::UserAccessor userAccessor(generator.context(), &requester);

  SECTION("it should return user ids it did not find")
  {
    REQUIRE_CALL(requester, getUsers(ANY(gsl::span<Trustchain::UserId const>), Tanker::Users::IRequester::IsLight::No))
        .RETURN(makeCoTask(Tanker::Users::IRequester::GetResult{generator.rootBlock(), {}}));

    std::vector ids{bob.id(), charlie.id()};
    std::sort(ids.begin(), ids.end());
    auto const result = AWAIT(userAccessor.pull(ids));
    CHECK(result.found.empty());
    CHECK(result.notFound == ids);
  }

  SECTION("it should return found users")
  {
    std::vector ids{alice.id(), bob.id(), charlie.id()};
    std::sort(ids.begin(), ids.end());

    REQUIRE_CALL(requester, getUsers(ids, Tanker::Users::IRequester::IsLight::No))
        .RETURN(makeCoTask(Tanker::Users::IRequester::GetResult{generator.rootBlock(),
                                                                generator.makeEntryList({alice, bob, charlie})}));
    auto result = AWAIT(userAccessor.pull(ids));
    CHECK(result.notFound.empty());
    auto expectedUsers = std::vector<Users::User>{alice, bob, charlie};

    std::sort(result.found.begin(), result.found.end());
    std::sort(expectedUsers.begin(), expectedUsers.end());
    CHECK(result.found == expectedUsers);
  }

  SECTION("it should return unique users")
  {
    std::vector ids{alice.id(), alice.id()};

    REQUIRE_CALL(requester, getUsers(std::vector{alice.id()}, Tanker::Users::IRequester::IsLight::No))
        .RETURN(
            makeCoTask(Tanker::Users::IRequester::GetResult{generator.rootBlock(), generator.makeEntryList({alice})}));
    auto result = AWAIT(userAccessor.pull(ids));

    CHECK(result.notFound.empty());
    CHECK(result.found == std::vector<Users::User>{alice});
  }
}
