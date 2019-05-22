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
    auto core1 = TC_AWAIT(device1.open());

    auto device2 = alice.makeDevice();
    auto core2 = device2.createCore(Test::SessionType::New);

    auto const password = Password{"my password"};
    auto const newPassword = Password{"new password"};
    auto const email = Email{"kirby@dreamland.nes"};
    auto const newEmail = Email{"bowser@dreamland.net"};

    SUBCASE("it creates an verificationKey and use it to add a third device")
    {
      auto verificationKey =
          TC_AWAIT(core1->generateAndRegisterVerificationKey());
      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(verificationKey)));
    }

    SUBCASE("it registers an unlock password and unlocks a new device")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(password))));
      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(core2->verifyIdentity(password));
    }

    SUBCASE("it registers an unlock email and unlocks a new device")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::RegistrationOptions{}.set(email))));

      auto const code = TC_AWAIT(getVerificationCode(email));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(TC_AWAIT(
          core2->verifyIdentity(Unlock::EmailVerification{email, code})));
    }

    SUBCASE("it registers an unlock password then re-registers a new one")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::RegistrationOptions{}.set(password))));
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::RegistrationOptions{}.set(newPassword))));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(core2->verifyIdentity(newPassword));
    }

    SUBCASE("it throws when trying to unlock with an invalid password")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(password))));

      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      CHECK_THROWS_AS(TC_AWAIT(core2->verifyIdentity(Password{"wrong pass"})),
                      Tanker::Error::InvalidUnlockPassword);
    }

    SUBCASE("it throws when trying to unlock with an invalid verification code")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(email))));

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
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(email))));

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
        "it throws when trying to unlock when register has not been done, with "
        "a password")
    {
      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      CHECK_THROWS(TC_AWAIT(core2->verifyIdentity(password)));
    }

    SUBCASE(
        "it throws when trying to unlock when register has not been done, with "
        "a verification code")
    {
      REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
                 Status::IdentityVerificationNeeded);
      CHECK_THROWS(TC_AWAIT(core2->verifyIdentity(
          Unlock::EmailVerification{email, VerificationCode{"code"}})));
    }
  }
}
