#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_SUITE("Unlock")
{
  TEST_CASE_FIXTURE(TrustchainFixture, "Unlock functions")
  {
    auto alice = trustchain.makeUser(Test::UserType::New);
    auto device1 = alice.makeDevice();
    auto core1 = device1.createCore(Test::SessionType::New);
    REQUIRE_EQ(TC_AWAIT(core1->start(alice.identity)),
               Status::IdentityRegistrationNeeded);

    auto device2 = alice.makeDevice();
    auto core2 = device2.createCore(Test::SessionType::New);

    auto const password = Password{"my password"};
    auto const newPassword = Password{"new password"};
    auto const email = Email{"kirby@dreamland.nes"};
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    auto const newEmail = Email{"bowser@dreamland.net"};

    SUBCASE("it creates an verificationKey and use it to add a third device")
    {
      auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
      TC_AWAIT(core1->registerIdentity(verificationKey));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(verificationKey)));
    }

    SUBCASE("it sets a validation password and unlocks a new device")
    {
      REQUIRE_NOTHROW(
          TC_AWAIT(core1->registerIdentity(Unlock::Verification{password})));
      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(core2->verifyIdentity(password));
    }

    SUBCASE("it sets a validation email and unlocks a new device")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
          Unlock::EmailVerification{email, verificationCode}})));

      auto const code = TC_AWAIT(getVerificationCode(email));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(TC_AWAIT(
          core2->verifyIdentity(Unlock::EmailVerification{email, code})));
    }

    SUBCASE("it sets a validation password then re-registers a new one")
    {
      REQUIRE_NOTHROW(
          TC_AWAIT(core1->registerIdentity(Unlock::Verification{password})));
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->setVerificationMethod(Unlock::Verification{newPassword})));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(core2->verifyIdentity(newPassword));
    }

    SUBCASE("it throws when trying to unlock with an invalid password")
    {
      REQUIRE_NOTHROW(
          TC_AWAIT(core1->registerIdentity(Unlock::Verification{password})));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      CHECK_THROWS_AS(TC_AWAIT(core2->verifyIdentity(Password{"wrongPass"})),
                      Tanker::Error::InvalidUnlockPassword);
    }

    SUBCASE(
        "it throws when trying to unlock with an invalid verification "
        "code")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
          Unlock::EmailVerification{email, verificationCode}})));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      CHECK_THROWS_AS(TC_AWAIT(core2->verifyIdentity(Unlock::EmailVerification{
                          email, VerificationCode{"d3JvbmcK"}})),
                      Tanker::Error::InvalidVerificationCode);
    }

    SUBCASE(
        "it fails to unlock after trying too many times with an invalid "
        "verification code")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
          Unlock::EmailVerification{email, verificationCode}})));

      auto const code = TC_AWAIT(getVerificationCode(email));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      for (int i = 0; i < 3; ++i)
        CHECK_THROWS_AS(
            TC_AWAIT(core2->verifyIdentity(Unlock::EmailVerification{
                email, VerificationCode{"d3JvbmcK"}})),
            Tanker::Error::InvalidVerificationCode);
      CHECK_THROWS_AS(TC_AWAIT(core2->verifyIdentity(Unlock::Verification{
                          Unlock::EmailVerification{email, code}})),
                      Tanker::Error::MaxVerificationAttemptsReached);
    }

    SUBCASE(
        "it throws when trying to unlock when register has not been done, "
        "with a password")
    {
      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityRegistrationNeeded);
      CHECK_THROWS(TC_AWAIT(core2->verifyIdentity(password)));
    }

    SUBCASE(
        "it throws when trying to unlock when register has not been done, "
        "with a verification code")
    {
      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityRegistrationNeeded);
      CHECK_THROWS(TC_AWAIT(core2->verifyIdentity(
          Unlock::EmailVerification{email, verificationCode})));
    }
  }
}
