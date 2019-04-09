#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>

#include <doctest.h>

namespace Tanker
{

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

    SUBCASE("it creates an unlockKey and use it to add a third device")
    {
      auto unlockKey = TC_AWAIT(core1->generateAndRegisterUnlockKey());

      REQUIRE_EQ(
          TC_AWAIT(core2->signIn(
              alice.identity,
              SignInOptions{unlockKey, nonstd::nullopt, nonstd::nullopt})),
          OpenResult::Ok);
    }

    SUBCASE("it registers an unlock password and unlocks a new device")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(password))));

      REQUIRE_EQ(
          TC_AWAIT(core2->signIn(
              alice.identity,
              SignInOptions{nonstd::nullopt, nonstd::nullopt, password})),
          OpenResult::Ok);
    }

    SUBCASE("it registers an unlock email and unlocks a new device")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::RegistrationOptions{}.set(email))));

      auto const code = TC_AWAIT(getVerificationCode(email));

      REQUIRE_EQ(TC_AWAIT(core2->signIn(
                     alice.identity,
                     SignInOptions{nonstd::nullopt, code, nonstd::nullopt})),
                 OpenResult::Ok);
    }

    SUBCASE("it registers an unlock password then re-registers a new one")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::RegistrationOptions{}.set(password))));
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::RegistrationOptions{}.set(newPassword))));

      REQUIRE_EQ(
          TC_AWAIT(core2->signIn(
              alice.identity,
              SignInOptions{nonstd::nullopt, nonstd::nullopt, newPassword})),
          OpenResult::Ok);
    }

    SUBCASE("it throws when trying to unlock with an invalid password")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(password))));

      CHECK_THROWS_AS(
          TC_AWAIT(core2->signIn(
              alice.identity,
              SignInOptions{
                  nonstd::nullopt, nonstd::nullopt, Password{"wrong pass"}})),
          Tanker::Error::InvalidUnlockPassword);
    }

    SUBCASE("it throws when trying to unlock with an invalid verification code")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(email))));

      CHECK_THROWS_AS(
          TC_AWAIT(core2->signIn(alice.identity,
                                 SignInOptions{nonstd::nullopt,
                                               VerificationCode{"d3JvbmcK"},
                                               nonstd::nullopt})),
          Tanker::Error::InvalidVerificationCode);
    }

    SUBCASE(
        "it fails to unlock after trying too many times with an invalid "
        "verification code")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::CreationOptions{}.set(email))));

      auto const code = TC_AWAIT(getVerificationCode(email));

      for (int i = 0; i < 3; ++i)
        CHECK_THROWS_AS(
            TC_AWAIT(core2->signIn(alice.identity,
                                   SignInOptions{nonstd::nullopt,
                                                 VerificationCode{"d3JvbmcK"},
                                                 nonstd::nullopt})),
            Tanker::Error::InvalidVerificationCode);
      CHECK_THROWS_AS(
          TC_AWAIT(core2->signIn(
              alice.identity,
              SignInOptions{nonstd::nullopt, code, nonstd::nullopt})),
          Tanker::Error::MaxVerificationAttemptsReached);
    }

    SUBCASE(
        "it throws when trying to unlock when register has not been done, with "
        "a password")
    {
      CHECK_THROWS(TC_AWAIT(core2->signIn(
          alice.identity,
          SignInOptions{nonstd::nullopt, nonstd::nullopt, password})));
    }

    SUBCASE(
        "it throws when trying to unlock when register has not been done, with "
        "a verification code")
    {
      CHECK_THROWS(TC_AWAIT(core2->signIn(
          alice.identity,
          SignInOptions{
              nonstd::nullopt, VerificationCode{"code"}, nonstd::nullopt})));
    }
  }
}
}
