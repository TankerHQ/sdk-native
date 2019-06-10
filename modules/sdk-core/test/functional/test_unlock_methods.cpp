#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_SUITE("Unlock")
{
  TEST_CASE_FIXTURE(TrustchainFixture, "Unlock Methods")
  {
    auto alice = trustchain.makeUser(Test::UserType::New);
    auto device1 = alice.makeDevice();
    auto core1 = device1.createCore(Test::SessionType::New);
    REQUIRE_EQ(TC_AWAIT(core1->start(alice.identity)),
               Status::IdentityRegistrationNeeded);
    auto const email = Email{"alice@yahou.com"};

    SUBCASE("It can test if some unlock method are registered")
    {
      auto const verificationCode = TC_AWAIT(getVerificationCode(email));
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
          Unlock::EmailVerification{email, verificationCode}})));
      auto const method = TC_AWAIT(core1->getVerificationMethods());

      FAST_CHECK_UNARY(!method.empty());
    }

    SUBCASE("It can test if email unlock method is registered")
    {
      auto const verificationCode = TC_AWAIT(getVerificationCode(email));
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
          Unlock::EmailVerification{email, verificationCode}})));

      auto const method = TC_AWAIT(core1->getVerificationMethods());
      REQUIRE(method.size() == 1);
      auto const verifEmail = method[0].get_if<Email>();
      REQUIRE(verifEmail);
      CHECK(*verifEmail == email);
    }

    SUBCASE("It can test if password unlock method is registered")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(
          Unlock::Verification{Password{"my password"}})));
      auto const method = TC_AWAIT(core1->getVerificationMethods());
      REQUIRE(method.size() == 1);
      FAST_CHECK_UNARY(method[0].holds_alternative<Password>());
    }

    SUBCASE("It can list all unlock methods registered")
    {
      auto const verificationCode = TC_AWAIT(getVerificationCode(email));
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(
          Unlock::Verification{Password{"my password"}})));
      REQUIRE_NOTHROW(
          TC_AWAIT(core1->setVerificationMethod(Unlock::Verification{
              Unlock::EmailVerification{email, verificationCode}})));
      auto const methods = TC_AWAIT(core1->getVerificationMethods());
      REQUIRE(methods.size() == 2);
    }
  }
}
