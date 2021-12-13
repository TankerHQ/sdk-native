#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Format/StringView.hpp>
#include <Tanker/Functional/Provisional.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Config.hpp>
#include <Helpers/Errors.hpp>
#include <Tanker/GhostDevice.hpp>

#include <Tanker/Cacerts/InitSsl.hpp>

#include <mgs/base64url.hpp>

#include <fetchpp/fetch.hpp>

#include <tconcurrent/asio_use_future.hpp>

#include <nlohmann/json.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>

#include <Tanker/Format/Enum.hpp>

#include <catch2/catch.hpp>

#include <string>

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;

namespace
{
void checkVerificationMethods(
    std::vector<Verification::VerificationMethod> actual,
    std::vector<Verification::VerificationMethod> expected)
{
  std::sort(actual.begin(), actual.end());
  std::sort(expected.begin(), expected.end());
  if (actual != expected)
    throw std::runtime_error("check failed: verification methods do not match");
}

tc::cotask<Tanker::Status> expectVerification(
    Functional::AsyncCorePtr session,
    std::string const& identity,
    Verification::Verification const& verification)
{
  REQUIRE(TC_AWAIT(session->start(identity)) ==
          Status::IdentityVerificationNeeded);
  TC_AWAIT(session->verifyIdentity(verification));
  checkVerificationMethods(
      TC_AWAIT(session->getVerificationMethods()),
      {Verification::VerificationMethod::from(verification)});
  TC_RETURN(session->status());
}

tc::cotask<OidcIdToken> getOidcToken(TestConstants::OidcConfig& oidcConfig,
                                     std::string userName)
{
  auto const payload = nlohmann::json{
      {"client_id", oidcConfig.clientId},
      {"client_secret", oidcConfig.clientSecret},
      {"grant_type", "refresh_token"},
      {"refresh_token", oidcConfig.users.at(userName).refreshToken},
  };

  using namespace fetchpp;

  auto const url = http::url("https://www.googleapis.com/oauth2/v4/token");
  auto req = http::request(http::verb::post, url);
  req.content(payload.dump());
  auto response = TC_AWAIT(fetchpp::async_fetch(
      tc::get_default_executor().get_io_service().get_executor(),
      Cacerts::get_ssl_context(),
      std::move(req),
      tc::asio::use_future));
  if (response.result() != http::status::ok)
    throw Errors::formatEx(Errors::Errc::NetworkError,
                           "invalid status google id token request: {}: {}",
                           response.result_int(),
                           http::obsolete_reason(response.result()));

  TC_RETURN(response.json().at("id_token").get<OidcIdToken>());
}
}

TEST_CASE_METHOD(
    TrustchainFixture,
    "The session must be closed after a conflicting verification attempt")
{
  auto alice = trustchain.makeUser();
  auto verificationKey = TC_AWAIT(registerUser(alice));

  // we loop for a bit, hoping for the race to trigger itself
  for (auto i = 1; i <= 10; ++i)
  {
    auto device1 = alice.makeDevice();
    auto device2 = alice.makeDevice();
    auto core1 = device1.createCore();
    auto core2 = device2.createCore();

    TC_AWAIT(core1->start(alice.identity));
    TC_AWAIT(core2->start(alice.identity));
    try
    {
      std::array<tc::future<void>, 2> futs;
      futs[0] =
          core1->verifyIdentity(VerificationKey{verificationKey}).to_void();
      futs[1] =
          core2->verifyIdentity(VerificationKey{verificationKey}).to_void();
      auto res =
          TC_AWAIT(tc::when_all(std::make_move_iterator(std::begin(futs)),
                                std::make_move_iterator(std::end(futs))));

      // we get() the futures to make them throw
      res[0].get();
      res[1].get();
      INFO(fmt::format("racing lap {}/10", i));
      CHECK(core2->status() == Status::Ready);
      CHECK(core1->status() == Status::Ready);
    }
    catch (Tanker::Errors::Exception const& ex)
    {
      CAPTURE(core1->status());
      CAPTURE(core2->status());
      CHECK(((core2->status() == Status::Stopped &&
              core1->status() == Status::Ready) ||
             (core1->status() == Status::Stopped &&
              core2->status() == Status::Ready)));
      break;
    }
    TC_AWAIT(core2->stop());
    TC_AWAIT(core1->stop());
    if (i == 10)
      FAIL("The race has not been triggered for 10 iterations");
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE(TC_AWAIT(core1->start(alice.identity)) ==
          Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const passphrase = Passphrase{"my passphrase"};
  auto const email = Email{"kirby@tanker.io"};
  auto const phoneNumber = PhoneNumber{"+33639982233"};

  SECTION("registerIdentity throws if passphrase is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(Passphrase{""})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if email is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(
            Verification::ByEmail{Email{""}, VerificationCode{"12345678"}})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if phone number is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(Verification::ByPhoneNumber{
            PhoneNumber{""}, VerificationCode{"12345678"}})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if verificationCode is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(
            Verification::ByEmail{email, VerificationCode{""}})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if OidcIdToken is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(OidcIdToken{""})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if verificationKey is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(VerificationKey{""})),
        Errc::InvalidVerification);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "registerIdentity throws adequate exception when verificationKey public "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    auto ghostDevice =
        nlohmann::json::parse(mgs::base64::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the public signature key
    ghostDevice.privateSignatureKey[2]++;
    verificationKey = VerificationKey{
        mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "registerIdentity throws adequate exception when verificationKey private "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    auto ghostDevice =
        nlohmann::json::parse(mgs::base64::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the private signature key
    ghostDevice.privateSignatureKey[60]++;
    verificationKey = VerificationKey{
        mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "verify identity throws adequate exceptions when verificationKey public "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice =
        nlohmann::json::parse(mgs::base64::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the public signature key
    ghostDevice.privateSignatureKey[2]++;
    verificationKey = VerificationKey{
        mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(mgs::base64::decode(alice.identity))
            .get<Identity::SecretPermanentIdentity>();
    auto identity =
        mgs::base64::encode(nlohmann::ordered_json(aliceIdentity).dump());

    CHECK(TC_AWAIT(core2->start(identity)) ==
          Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "verify identity throws adequate exceptions when verificationKey private "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice =
        nlohmann::json::parse(mgs::base64::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the private signature key
    ghostDevice.privateSignatureKey[60]++;
    verificationKey = VerificationKey{
        mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(mgs::base64::decode(alice.identity))
            .get<Identity::SecretPermanentIdentity>();
    auto identity =
        mgs::base64::encode(nlohmann::ordered_json(aliceIdentity).dump());

    CHECK(TC_AWAIT(core2->start(identity)) ==
          Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "verify identity throws adequate exceptions when verificationKey private "
      "encryption key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice =
        nlohmann::json::parse(mgs::base64::decode(verificationKey))
            .get<GhostDevice>();
    // Corrupt the private encryption key
    ghostDevice.privateEncryptionKey[2]++;
    verificationKey = VerificationKey{
        mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(mgs::base64::decode(alice.identity))
            .get<Identity::SecretPermanentIdentity>();
    auto identity =
        mgs::base64::encode(nlohmann::ordered_json(aliceIdentity).dump());

    CHECK(TC_AWAIT(core2->start(identity)) ==
          Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("it creates an verificationKey and use it to add a second device")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {VerificationKey{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(verificationKey)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {VerificationKey{}}));
  }

  SECTION("it sets a passphrase and adds a new device")
  {
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {Passphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
  }

  SECTION("it gets verification methods before verifying identity")
  {
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
  }

  SECTION("it sets an email and adds a new device")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(
        core2->verifyIdentity(Verification::ByEmail{email, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {email}));
  }

  SECTION("it sets a phone number and adds a new device")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {phoneNumber}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(
        Verification::ByPhoneNumber{phoneNumber, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {phoneNumber}));
  }

  SECTION("it updates a verification passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    auto const newPassphrase = Passphrase{"new passphrase"};
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{newPassphrase})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(newPassphrase)));
  }

  SECTION("it sets a phone number and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}})));

    REQUIRE_NOTHROW(TC_AWAIT(
        core1->setVerificationMethod(Verification::Verification{passphrase})));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {phoneNumber, Passphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()),
                                 {phoneNumber, Passphrase{}}));
  }

  SECTION("it sets an email and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    REQUIRE_NOTHROW(TC_AWAIT(
        core1->setVerificationMethod(Verification::Verification{passphrase})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email, Passphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {email, Passphrase{}}));
  }

  SECTION(
      "it fails to set a verification method after using a verification key")
  {
    auto const verificationKey = TC_AWAIT(core1->generateVerificationKey());
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{verificationKey})));

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->setVerificationMethod(
                                      Verification::Verification{passphrase})),
                                  Errc::PreconditionFailed);
  }

  SECTION("it fails to set a verification key after a verification method ")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Passphrase{"new passphrase"}})));

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->generateVerificationKey()),
                                  Errc::PreconditionFailed);
  }

  SECTION("it throws when trying to verify with an invalid passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(Passphrase{"wrongPass"})),
        Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("it throws when trying to verify with an invalid verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(
            Verification::ByEmail{email, VerificationCode{"00000000"}})),
        Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "it fails to unlock after trying too many times with an invalid "
      "verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    auto const code = TC_AWAIT(getVerificationCode(email));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);
    for (int i = 0; i < 3; ++i)
    {
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(core2->verifyIdentity(
              Verification::ByEmail{email, VerificationCode{"00000000"}})),
          Errc::InvalidVerification);
      REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
    }
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(
            Verification::Verification{Verification::ByEmail{email, code}})),
        Errc::TooManyAttempts);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("it throws when trying to verify before registration")
  {
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->verifyIdentity(passphrase)),
                                  Errc::PreconditionFailed);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("It updates email verification method on setVerificationMethods")
  {
    // register
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    // update email
    auto const newEmail = Email{"alice.test@tanker.io"};
    verificationCode = TC_AWAIT(getVerificationCode(newEmail));
    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{
        Verification::ByEmail{newEmail, verificationCode}}));

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

  SECTION(
      "It updates phone number verification method on setVerificationMethods")
  {
    // register
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    // update phone number
    auto const newPhoneNumber = PhoneNumber{"+33639982244"};
    verificationCode = TC_AWAIT(getVerificationCode(newPhoneNumber));
    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{
        Verification::ByPhoneNumber{newPhoneNumber, verificationCode}}));

    // check that phoneNumber is updated in cache
    auto methods = TC_AWAIT(core1->getVerificationMethods());
    REQUIRE(methods.size() == 1);
    CHECK(methods[0].get<PhoneNumber>() == newPhoneNumber);

    // reconnect
    TC_AWAIT(core1->stop());
    TC_AWAIT(core1->start(alice.identity));

    // check that phone number is ok
    methods = TC_AWAIT(core1->getVerificationMethods());
    REQUIRE(methods.size() == 1);
    CHECK(methods[0].get<PhoneNumber>() == newPhoneNumber);
  }

  SECTION(
      "setVerificationMethod with preverified email throws if preverified "
      "verification flag is "
      "disabled")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    auto const preverifiedEmail = PreverifiedEmail{"superkirby@tanker.io"};
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->setVerificationMethod(
            Verification::Verification{preverifiedEmail})),
        AppdErrc::FeatureNotEnabled);
  }

  SECTION(
      "setVerificationMethod with preverified phone number throws if "
      "preverified verification flag is disabled")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    auto const preverifiedPhoneNumber = PreverifiedPhoneNumber{"+33639982244"};
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->setVerificationMethod(
            Verification::Verification{preverifiedPhoneNumber})),
        AppdErrc::FeatureNotEnabled);
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification with preverified email")
{
  TC_AWAIT(enablePreverifiedMethods());
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE(TC_AWAIT(core1->start(alice.identity)) ==
          Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const email = Email{"kirby@tanker.io"};
  auto const phoneNumber = PhoneNumber{"+33639982233"};

  auto const preverifiedEmail = PreverifiedEmail{"superkirby@tanker.io"};
  auto const emailOfPreverifiedEmail = Email{preverifiedEmail.string()};

  SECTION(
      "registerIdentity throws when verification method is preverified email")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(preverifiedEmail)),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("verifyIdentity throws when verification method is preverified email")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(preverifiedEmail)),
        Errc::InvalidArgument);

    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "it registers with an email, updates to preverified email when calling "
      "setVerificationMethod, and updates to normal email when verifying")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedEmail}));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {preverifiedEmail}));

    TC_AWAIT(core2->start(alice.identity));
    verificationCode = TC_AWAIT(getVerificationCode(emailOfPreverifiedEmail));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(
        Verification::ByEmail{emailOfPreverifiedEmail, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {emailOfPreverifiedEmail}));
  }

  SECTION(
      "it register with an email, updates to preverified email when calling "
      "setVerificationMethod with the same email")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    auto const newPreverifiedEmail = PreverifiedEmail{"kirby@tanker.io"};
    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{newPreverifiedEmail}));

    // check that email is ok
    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {newPreverifiedEmail}));
  }

  SECTION(
      "It turns preverified email method into email method when calling "
      "setVerificationMethod")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedEmail}));

    verificationCode = TC_AWAIT(getVerificationCode(emailOfPreverifiedEmail));
    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{
        Verification::ByEmail{emailOfPreverifiedEmail, verificationCode}}));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {emailOfPreverifiedEmail}));
  }

  SECTION(
      "it turns preverified email method into email method when calling "
      "verifyProvisionalIdentity")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedEmail}));

    auto const secretProvisionalIdentity =
        SSecretProvisionalIdentity(Identity::createProvisionalIdentity(
            mgs::base64::encode(trustchain.id), emailOfPreverifiedEmail));
    auto const publicProvisionalIdentity = SPublicIdentity(
        Identity::getPublicIdentity(secretProvisionalIdentity.string()));

    auto const aliceProvisional =
        Functional::AppProvisionalUser{emailOfPreverifiedEmail,
                                       secretProvisionalIdentity,
                                       publicProvisionalIdentity};

    REQUIRE_NOTHROW(
        TC_AWAIT(attachProvisionalIdentity(*core1, aliceProvisional)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {emailOfPreverifiedEmail}));
  }

  SECTION("It adds preverified email as a new verification method")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedEmail}));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {phoneNumber, preverifiedEmail}));
  }
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Verification with preverified phone number")
{
  TC_AWAIT(enablePreverifiedMethods());
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE(TC_AWAIT(core1->start(alice.identity)) ==
          Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const email = Email{"kirby@tanker.io"};
  auto const phoneNumber = PhoneNumber{"+33639982233"};

  auto const preverifiedPhoneNumber = PreverifiedPhoneNumber{"+33639982244"};
  auto const phoneNumberOfPreverifiedPhoneNumber =
      PhoneNumber{preverifiedPhoneNumber.string()};

  SECTION(
      "registerIdentity throws when verification method is preverified phone "
      "number")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(
            PreverifiedPhoneNumber{preverifiedPhoneNumber})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "verifyIdentity throws when verification method is preverified phone "
      "number")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) ==
            Status::IdentityVerificationNeeded);

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(
            PreverifiedPhoneNumber{preverifiedPhoneNumber})),
        Errc::InvalidArgument);

    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "it registers with a phone number, updates to preverified phone number "
      "when calling setVerificationMethod, and updates to normal phone number "
      "when verifying")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedPhoneNumber}));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {preverifiedPhoneNumber}));

    TC_AWAIT(core2->start(alice.identity));
    verificationCode =
        TC_AWAIT(getVerificationCode(phoneNumberOfPreverifiedPhoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(Verification::ByPhoneNumber{
        phoneNumberOfPreverifiedPhoneNumber, verificationCode})));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {phoneNumberOfPreverifiedPhoneNumber}));
  }

  SECTION(
      "register with a phone number, updates to preverified phone number when "
      "calling setVerificationMethod with the same phone number")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    auto const newPreverifiedPhoneNumber =
        PreverifiedPhoneNumber{phoneNumber.string()};
    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{newPreverifiedPhoneNumber}));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {newPreverifiedPhoneNumber}));
  }

  SECTION(
      "It turns preverified phone number method into phone number method when "
      "calling setVerificationMethod")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedPhoneNumber}));

    verificationCode =
        TC_AWAIT(getVerificationCode(phoneNumberOfPreverifiedPhoneNumber));
    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{Verification::ByPhoneNumber{
            phoneNumberOfPreverifiedPhoneNumber, verificationCode}}));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {phoneNumberOfPreverifiedPhoneNumber}));
  }

  SECTION(
      "it turns preverified phone number method into phone number method when "
      "calling verifyProvisionalIdentity")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedPhoneNumber}));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {preverifiedPhoneNumber}));

    auto const secretProvisionalIdentity =
        SSecretProvisionalIdentity(Identity::createProvisionalIdentity(
            mgs::base64::encode(trustchain.id),
            phoneNumberOfPreverifiedPhoneNumber));
    auto const publicProvisionalIdentity = SPublicIdentity(
        Identity::getPublicIdentity(secretProvisionalIdentity.string()));

    auto const aliceProvisional =
        Functional::AppProvisionalUser{phoneNumberOfPreverifiedPhoneNumber,
                                       secretProvisionalIdentity,
                                       publicProvisionalIdentity};

    REQUIRE_NOTHROW(
        TC_AWAIT(attachProvisionalIdentity(*core1, aliceProvisional)));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {phoneNumberOfPreverifiedPhoneNumber}));
  }

  SECTION("It adds preverified phone number as a new verification method")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{preverifiedPhoneNumber}));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {email, preverifiedPhoneNumber}));
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification through oidc")
{
  TC_AWAIT(enableOidc());

  auto martine = trustchain.makeUser();
  auto martineDevice = martine.makeDevice();
  auto martineLaptop = martineDevice.createCore();
  REQUIRE(TC_AWAIT(martineLaptop->start(martine.identity)) ==
          Status::IdentityRegistrationNeeded);

  auto martineDevice2 = martine.makeDevice();
  auto martinePhone = martineDevice2.createCore();

  auto oidcConfig = TestConstants::oidcConfig();

  OidcIdToken martineIdToken, kevinIdToken;
  {
    martineIdToken = TC_AWAIT(getOidcToken(oidcConfig, "martine"));
    kevinIdToken = TC_AWAIT(getOidcToken(oidcConfig, "kevin"));
  }

  SECTION("")
  {
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(martineIdToken)));

    SECTION("registers and verifies identity with an oidc id token")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          expectVerification(martinePhone, martine.identity, martineIdToken)));
    }
    SECTION("fails to verify a token with incorrect signature")
    {
      namespace ba = boost::algorithm;
      using b64 = mgs::base64url_nopad;

      std::vector<std::string> res;
      auto itSig = ba::split(res, martineIdToken, ba::is_any_of(".")).rbegin();
      auto alterSig = b64::decode(*itSig);
      ++alterSig[5];
      *itSig = b64::encode(alterSig);

      auto const alteredToken = OidcIdToken{ba::join(res, ".")};
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(
              expectVerification(martinePhone, martine.identity, alteredToken)),
          Errc::InvalidVerification);
    }
    SECTION("fails to verify a valid token for the wrong user")
    {
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(
              expectVerification(martinePhone, martine.identity, kevinIdToken)),
          Errc::InvalidVerification);
    }
  }
  SECTION("")
  {
    auto const pass = Passphrase{"******"};
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(pass)));

    SECTION("updates and verifies with an oidc token")
    {
      REQUIRE_NOTHROW(
          TC_AWAIT(martineLaptop->setVerificationMethod(martineIdToken)));
      REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) ==
              Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(TC_AWAIT(martinePhone->verifyIdentity(martineIdToken)));
      REQUIRE_NOTHROW(checkVerificationMethods(
          TC_AWAIT(martinePhone->getVerificationMethods()),
          {Passphrase{}, OidcIdToken{}}));
    }
    SECTION(
        "fails to attach a provisional identity for the wrong google account")
    {
      auto const email = Email{"the-ceo@tanker.io"};
      auto const martineProvisionalIdentity =
          Identity::createProvisionalIdentity(
              mgs::base64::encode(trustchain.id), email);
      auto const result = TC_AWAIT(martineLaptop->attachProvisionalIdentity(
          SSecretProvisionalIdentity{martineProvisionalIdentity}));
      REQUIRE(result.status == Tanker::Status::IdentityVerificationNeeded);
      REQUIRE(result.verificationMethod == email);
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(martineLaptop->verifyProvisionalIdentity(martineIdToken)),
          Errc::InvalidArgument);
    }
    SECTION("decrypts data shared with an attached provisional identity")
    {
      auto alice = trustchain.makeUser();
      auto aliceDevice = alice.makeDevice();
      auto aliceLaptop = TC_AWAIT(aliceDevice.open());

      auto const martineEmail = Email{oidcConfig.users.at("martine").email};
      auto const martineProvisionalIdentity =
          Identity::createProvisionalIdentity(
              mgs::base64::encode(trustchain.id), martineEmail);

      auto const publicProvisionalId = SPublicIdentity{
          Identity::getPublicIdentity(martineProvisionalIdentity)};

      auto const clearText = make_buffer("this is some clear test");
      auto const encrypted =
          TC_AWAIT(aliceLaptop->encrypt(clearText, {publicProvisionalId}));

      auto const result = TC_AWAIT(martineLaptop->attachProvisionalIdentity(
          SSecretProvisionalIdentity{martineProvisionalIdentity}));
      REQUIRE(result.status == Tanker::Status::IdentityVerificationNeeded);
      REQUIRE(result.verificationMethod == martineEmail);
      TC_AWAIT(martineLaptop->verifyProvisionalIdentity(martineIdToken));
      auto const decrypted = TC_AWAIT(martineLaptop->decrypt(encrypted));
      REQUIRE(clearText == decrypted);
    }
  }
}
