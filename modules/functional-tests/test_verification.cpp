#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Errors.hpp>

#include <doctest.h>
#include <nlohmann/json.hpp>

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;

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
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore(Functional::SessionType::New);
  REQUIRE_EQ(TC_AWAIT(core1->start(alice.identity)),
             Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore(Functional::SessionType::New);

  auto const password = Passphrase{"my password"};
  auto const email = Email{"kirby@dreamland.nes"};

  SUBCASE(
      "registerIdentity throws adequate exception when verificationKey public "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    auto ghostDevice =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the public signature key
    ghostDevice.privateSignatureKey[2]++;
    verificationKey = VerificationKey{
        cppcodec::base64_rfc4648::encode(nlohmann::json(ghostDevice).dump())};

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(verificationKey)),
        Errc::InvalidVerification);
  }

  SUBCASE(
      "registerIdentity throws adequate exception when verificationKey private "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    auto ghostDevice =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the private signature key
    ghostDevice.privateSignatureKey[60]++;
    verificationKey = VerificationKey{
        cppcodec::base64_rfc4648::encode(nlohmann::json(ghostDevice).dump())};

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(verificationKey)),
        Errc::InvalidVerification);
  }

  SUBCASE(
      "verify identity throws adequate exceptions when verificationKey public "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the public signature key
    ghostDevice.privateSignatureKey[2]++;
    verificationKey = VerificationKey{
        cppcodec::base64_rfc4648::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(alice.identity))
            .get<Identity::SecretPermanentIdentity>();
    auto identity =
        cppcodec::base64_rfc4648::encode(nlohmann::json(aliceIdentity).dump());

    CHECK_EQ(TC_AWAIT(core2->start(identity)),
             Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
  }

  SUBCASE(
      "verify identity throws adequate exceptions when verificationKey private "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the private signature key
    ghostDevice.privateSignatureKey[60]++;
    verificationKey = VerificationKey{
        cppcodec::base64_rfc4648::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(alice.identity))
            .get<Identity::SecretPermanentIdentity>();
    auto identity =
        cppcodec::base64_rfc4648::encode(nlohmann::json(aliceIdentity).dump());

    CHECK_EQ(TC_AWAIT(core2->start(identity)),
             Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
  }

  SUBCASE(
      "verify identity throws adequate exceptions when verificationKey private "
      "encryption key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the private encryption key
    ghostDevice.privateEncryptionKey[2]++;
    verificationKey = VerificationKey{
        cppcodec::base64_rfc4648::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(cppcodec::base64_rfc4648::decode(alice.identity))
            .get<Identity::SecretPermanentIdentity>();
    auto identity =
        cppcodec::base64_rfc4648::encode(nlohmann::json(aliceIdentity).dump());

    CHECK_EQ(TC_AWAIT(core2->start(identity)),
             Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
  }

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
        TC_AWAIT(core1->getVerificationMethods()), {Passphrase{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(password)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
  }

  SUBCASE("it gets verification methods before verifying identity")
  {
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Unlock::Verification{password})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
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

    auto const newPassphrase = Passphrase{"new password"};
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->setVerificationMethod(Unlock::Verification{newPassphrase})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(newPassphrase)));
  }

  SUBCASE("it sets an email and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Unlock::Verification{
        Unlock::EmailVerification{email, verificationCode}})));

    REQUIRE_NOTHROW(
        TC_AWAIT(core1->setVerificationMethod(Unlock::Verification{password})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email, Passphrase{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(password)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {email, Passphrase{}}));
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
        TC_AWAIT(core2->verifyIdentity(Passphrase{"wrongPass"})),
        Errc::InvalidVerification);
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
        Errc::InvalidVerification);
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
          Errc::InvalidVerification);
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

  SUBCASE("It updates verification methods on setVerificationMethods")
  {
    // register
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Unlock::Verification{
        Unlock::EmailVerification{email, verificationCode}}));

    // update email
    auto const newEmail = Email{"alice@yoohoo.fr"};
    verificationCode = TC_AWAIT(getVerificationCode(newEmail));
    TC_AWAIT(core1->setVerificationMethod(Unlock::Verification{
        Unlock::EmailVerification{newEmail, verificationCode}}));

    // check that email is updated in cache
    auto methods = TC_AWAIT(core1->getVerificationMethods());
    REQUIRE(methods.size() == 1);
    CHECK(methods[0].get<Email>() == newEmail);

    // reconnect
    TC_AWAIT(core1->stop());
    TC_AWAIT(core1->start(alice.identity));

    // check that email is ok
    methods = TC_AWAIT(core1->getVerificationMethods());
    REQUIRE(methods.size() == 1);
    CHECK(methods[0].get<Email>() == newEmail);
  }
}
