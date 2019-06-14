#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Errors.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Errors;

namespace
{
void checkVerificationMethods(std::vector<Unlock::VerificationMethod> actual,
                              std::vector<Unlock::VerificationMethod> expected)
{
  std::sort(actual.begin(), actual.end());
  std::sort(expected.begin(), expected.end());
  if (actual != expected)
    throw std::runtime_error("check failed: verification methods do not match");
}
}

TEST_CASE_FIXTURE(TrustchainFixture, "Verification")
{
  auto alice = trustchain.makeUser(Test::UserType::New);
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore(Test::SessionType::New);
  REQUIRE_EQ(TC_AWAIT(core1->start(alice.identity)),
             Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore(Test::SessionType::New);

  auto const password = Password{"my password"};
  auto const email = Email{"kirby@dreamland.nes"};

  SUBCASE("it creates an verificationKey and use it to add a second device")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {VerificationKey{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(verificationKey)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {VerificationKey{}}));
  }

  SUBCASE("it sets a passphrase and adds a new device")
  {
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Unlock::Verification{password})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {Password{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(password)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {Password{}}));
  }

  SUBCASE("it sets an email and adds a new device")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
        Unlock::EmailVerification{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(
        Unlock::EmailVerification{email, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {email}));
  }

  SUBCASE("it updates a verification passphrase")
  {
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Unlock::Verification{password})));

    auto const newPassword = Password{"new password"};
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->setVerificationMethod(Unlock::Verification{newPassword})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(newPassword)));
  }

  SUBCASE("it sets an email and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
        Unlock::EmailVerification{email, verificationCode}})));

    REQUIRE_NOTHROW(
        TC_AWAIT(core1->setVerificationMethod(Unlock::Verification{password})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email, Password{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(password)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {email, Password{}}));
  }

  SUBCASE(
      "it fails to set a verification method after using a verification key")
  {
    auto const verificationKey = TC_AWAIT(core1->generateVerificationKey());
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Unlock::Verification{verificationKey})));

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->setVerificationMethod(Unlock::Verification{password})),
        Errc::PreconditionFailed);
  }

  SUBCASE("it throws when trying to verify with an invalid password")
  {
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Unlock::Verification{password})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(Password{"wrongPass"})),
        Errc::InvalidCredentials);
  }

  SUBCASE("it throws when trying to verify with an invalid verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
        Unlock::EmailVerification{email, verificationCode}})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(
            Unlock::EmailVerification{email, VerificationCode{"d3JvbmcK"}})),
        Errc::InvalidCredentials);
  }

  SUBCASE(
      "it fails to unlock after trying too many times with an invalid "
      "verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
        Unlock::EmailVerification{email, verificationCode}})));

    auto const code = TC_AWAIT(getVerificationCode(email));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    for (int i = 0; i < 3; ++i)
    {
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(core2->verifyIdentity(
              Unlock::EmailVerification{email, VerificationCode{"d3JvbmcK"}})),
          Errc::InvalidCredentials);
    }
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(
            Unlock::Verification{Unlock::EmailVerification{email, code}})),
        Errc::TooManyAttempts);
  }

  SUBCASE("it throws when trying to verify before registration")
  {
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(password)),
                                  Errc::PreconditionFailed);
  }
}
