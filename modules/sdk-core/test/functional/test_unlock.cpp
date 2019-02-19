#include <Tanker/Test/Functional/Trustchain.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Error.hpp>

#include "TrustchainFixture.hpp"

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

    SUBCASE("it creates an unlockKey and use it to add a third device")
    {
      auto unlockKey = TC_AWAIT(core1->generateAndRegisterUnlockKey());

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&unlockKey, &core2]() -> tc::cotask<void> {
          try
          {
            TC_AWAIT(core2->unlockCurrentDevice(unlockKey));
          }
          catch (std::exception const& e)
          {
            FAIL(e.what());
          }
        });
      });

      REQUIRE_NOTHROW(
          TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
    }

    SUBCASE("it register an unlock password and unlock a new device")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Password{"my password"}))));

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&core2]() -> tc::cotask<void> {
          try
          {
            TC_AWAIT(core2->unlockCurrentDevice(Password{"my password"}));
          }
          catch (std::exception const& e)
          {
            FAIL(e.what());
            core2->close();
          }
        });
      });

      REQUIRE_NOTHROW(
          TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
    }

    SUBCASE("it register an unlock email and unlock a new device")
    {
      auto const email = Email{"kirby@dreamland.nes"};
      REQUIRE_NOTHROW(TC_AWAIT(
          core1->registerUnlock(Unlock::RegistrationOptions{}.set(email))));

      auto const code =
          TC_AWAIT(trustchain.getVerificationCode(alice.suserId(), email));
      core2->unlockRequired().connect([&] {
        tc::async_resumable([&]() -> tc::cotask<void> {
          try
          {
            TC_AWAIT(core2->unlockCurrentDevice(code));
          }
          catch (std::exception const& e)
          {
            FAIL(e.what());
            core2->close();
          }
        });
      });

      REQUIRE_NOTHROW(
          TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
    }

    SUBCASE("it register an unlock password then re-register a new one")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::RegistrationOptions{}.set(Password{"my password"}))));
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::RegistrationOptions{}.set(Password{"my new password"}))));

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&core2]() -> tc::cotask<void> {
          try
          {
            TC_AWAIT(core2->unlockCurrentDevice(Password{"my new password"}));
          }
          catch (std::exception const& e)
          {
            FAIL(e.what());
            core2->close();
          }
        });
      });

      REQUIRE_NOTHROW(
          TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
    }

    SUBCASE("it throws when trying to unlock with an invalid password")
    {

      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Password{"my password"}))));

      bool ok = false;

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&core2, &ok]() -> tc::cotask<void> {
          CHECK_THROWS_AS(
              TC_AWAIT(core2->unlockCurrentDevice(Password{"wrong password"})),
              Tanker::Error::InvalidUnlockPassword);
          ok = true;
          // we close to cancel the open() below
          TC_AWAIT(core2->close());
        });
      });

      REQUIRE_THROWS(TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
      REQUIRE(ok);
    }

    SUBCASE("it throws when trying to unlock with an invalid verification code")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Email{"bowser@dreamland.net"}))));

      bool ok = false;

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&core2, &ok]() -> tc::cotask<void> {
          CHECK_THROWS_AS(TC_AWAIT(core2->unlockCurrentDevice(
                              VerificationCode{"d3JvbmcK"})),
                          Tanker::Error::InvalidVerificationCode);
          ok = true;
          // we close to cancel the open() below
          TC_AWAIT(core2->close());
        });
      });

      REQUIRE_THROWS(TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
      REQUIRE(ok);
    }

    SUBCASE(
        "it fails to unlock after trying too many times with an invalid "
        "verification code")
    {
      REQUIRE_NOTHROW(TC_AWAIT(core1->registerUnlock(
          Unlock::CreationOptions{}.set(Email{"bowser@dreamland.net"}))));

      bool ok = false;
      auto const code = TC_AWAIT(trustchain.getVerificationCode(
          alice.suserId(), Email{"bowser@dreamland.net"}));

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&]() -> tc::cotask<void> {
          CHECK_THROWS_AS(TC_AWAIT(core2->unlockCurrentDevice(
                              VerificationCode{"d3JvbmcK"})),
                          Tanker::Error::InvalidVerificationCode);
          CHECK_THROWS_AS(TC_AWAIT(core2->unlockCurrentDevice(
                              VerificationCode{"d3JvbmcK"})),
                          Tanker::Error::InvalidVerificationCode);
          CHECK_THROWS_AS(TC_AWAIT(core2->unlockCurrentDevice(
                              VerificationCode{"d3JvbmcK"})),
                          Tanker::Error::InvalidVerificationCode);
          REQUIRE_THROWS_AS(TC_AWAIT(core2->unlockCurrentDevice(code)),
                            Tanker::Error::MaxVerificationAttemptsReached);
          ok = true;
          // we close to cancel the open() below
          TC_AWAIT(core2->close());
        });
      });

      REQUIRE_THROWS(TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
      REQUIRE(ok);
    }

    SUBCASE(
        "it throws when trying to unlock when register has not been done, with "
        "a password")
    {
      bool ok = false;

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&core2, &ok]() -> tc::cotask<void> {
          CHECK_THROWS_AS(
              TC_AWAIT(core2->unlockCurrentDevice(Password{"password"})),
              Tanker::Error::InvalidUnlockKey);
          ok = true;
          // we close to cancel the open() below
          TC_AWAIT(core2->close());
        });
      });

      REQUIRE_THROWS(TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
      REQUIRE(ok);
    }

    SUBCASE(
        "it throws when trying to unlock when register has not been done, with "
        "a verification code")
    {
      bool ok = false;

      core2->unlockRequired().connect([&] {
        tc::async_resumable([&core2, &ok]() -> tc::cotask<void> {
          CHECK_THROWS_AS(TC_AWAIT(core2->unlockCurrentDevice(
                              VerificationCode{"d3JvbmcK"})),
                          Tanker::Error::InvalidUnlockKey);
          ok = true;
          // we close to cancel the open() below
          TC_AWAIT(core2->close());
        });
      });

      REQUIRE_THROWS(TC_AWAIT(core2->open(alice.suserId(), alice.userToken())));
      REQUIRE(ok);
    }
  }
}
}
