#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_SUITE("Unlock")
{
  TEST_CASE_FIXTURE(TrustchainFixture, "Unlock Methods")
  {
    auto alice = trustchain.makeUser(Test::UserType::New);
    auto device1 = alice.makeDevice();
    auto core1 = TC_AWAIT(device1.open());

    SUBCASE("It can test if some unlock method are registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
          Unlock::Verification{Unlock::EmailVerification{
              Email{"alice@yahou.com"}, VerificationCode{}}})));
      auto const method = TC_AWAIT(core1->hasRegisteredUnlockMethods());

      FAST_CHECK_UNARY(method);
    }

    SUBCASE("It can test if email unlock method is registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
          Unlock::Verification{Unlock::EmailVerification{
              Email{"alice@yahou.com"}, VerificationCode{}}})));

      auto const method =
          TC_AWAIT(core1->hasRegisteredUnlockMethod(Unlock::Method::Email));
      FAST_CHECK_UNARY(method);
    }

    SUBCASE("It can test if password unlock method is registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
          Unlock::Verification{Password{"my password"}})));
      auto const method =
          TC_AWAIT(core1->hasRegisteredUnlockMethod(Unlock::Method::Password));
      FAST_CHECK_UNARY(method);
    }

    SUBCASE("It can list all unlock methods registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
          Unlock::Verification{Password{"my password"}})));
      REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
          Unlock::Verification{Unlock::EmailVerification{
              Email{"alice@yahou.com"}, VerificationCode{}}})));
      auto const methods = TC_AWAIT(core1->registeredUnlockMethods());

      FAST_CHECK_UNARY(methods & Unlock::Method::Password);
      FAST_CHECK_UNARY(methods & Unlock::Method::Email);
      FAST_CHECK_EQ(methods,
                    (Unlock::Method::Email | Unlock::Method::Password));
    }
  }
}
