#include <Tanker/Test/Functional/Trustchain.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>

#include "TrustchainFixture.hpp"

#include <doctest.h>

namespace Tanker
{
TEST_SUITE("Unlock")
{
  TEST_CASE_FIXTURE(TrustchainFixture, "Unlock Methods")
  {
    auto alice = trustchain.makeUser(Test::UserType::New);
    auto device1 = alice.makeDevice();
    auto core1 = TC_AWAIT(device1.open());

    SUBCASE("It can test if unlock is set up")
    {
      CHECK_UNARY_FALSE(TC_AWAIT(core1->isUnlockAlreadySetUp()));
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Password{"my password"}))));
      TC_AWAIT(core1->syncTrustchain());
      CHECK_UNARY(TC_AWAIT(core1->isUnlockAlreadySetUp()));
    }

    SUBCASE("It can test if some unlock method are registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Email{"alice@yahou.com"}))));
      auto const method = TC_AWAIT(core1->hasRegisteredUnlockMethods());

      FAST_CHECK_UNARY(method);
    }

    SUBCASE("It can test if email unlock method is registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Email{"alice@yahou.com"}))));
      auto const method =
          TC_AWAIT(core1->hasRegisteredUnlockMethods(Unlock::Method::Email));
      FAST_CHECK_UNARY(method);
    }

    SUBCASE("It can test if password unlock method is registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Password{"my password"}))));
      auto const method =
          TC_AWAIT(core1->hasRegisteredUnlockMethods(Unlock::Method::Password));
      FAST_CHECK_UNARY(method);
    }

    SUBCASE("It can list all unlock methods registered")
    {
      REQUIRE_NOTHROW(
          TC_AWAIT(core1->registerUnlock(Unlock::CreationOptions{}
                                             .set(Password{"my password"})
                                             .set(Email{"alice@yahou.com"}))));
      auto const methods = TC_AWAIT(core1->registeredUnlockMethods());

      FAST_CHECK_UNARY(methods & Unlock::Method::Password);
      FAST_CHECK_UNARY(methods & Unlock::Method::Email);
      FAST_CHECK_EQ(methods,
                    (Unlock::Method::Email | Unlock::Method::Password));
    }
  }
}
}
