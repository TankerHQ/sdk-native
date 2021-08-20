#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
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

#include <doctest/doctest.h>

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
  REQUIRE_EQ(TC_AWAIT(session->start(identity)),
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

TEST_CASE_FIXTURE(TrustchainFixture, "Verification")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE_EQ(TC_AWAIT(core1->start(alice.identity)),
             Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const passphrase = Passphrase{"my passphrase"};
  auto const email = Email{"kirby@tanker.io"};
  auto const phoneNumber = PhoneNumber{"+33639982233"};

  SUBCASE("registerIdentity throws if passphrase is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(Passphrase{""})),
        Errc::InvalidArgument);
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE("registerIdentity throws if email is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(
            Verification::ByEmail{Email{""}, VerificationCode{"12345678"}})),
        Errc::InvalidArgument);
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE("registerIdentity throws if phone number is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(Verification::ByPhoneNumber{
            PhoneNumber{""}, VerificationCode{"12345678"}})),
        Errc::InvalidArgument);
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE("registerIdentity throws if verificationCode is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(
            Verification::ByEmail{email, VerificationCode{""}})),
        Errc::InvalidArgument);
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE("registerIdentity throws if OidcIdToken is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(OidcIdToken{""})),
        Errc::InvalidArgument);
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE("registerIdentity throws if verificationKey is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(VerificationKey{""})),
        Errc::InvalidVerification);
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE(
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
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE(
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
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE(
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

    CHECK_EQ(TC_AWAIT(core2->start(identity)),
             Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE_EQ(core2->status(), Status::IdentityVerificationNeeded);
  }

  SUBCASE(
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

    CHECK_EQ(TC_AWAIT(core2->start(identity)),
             Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE_EQ(core2->status(), Status::IdentityVerificationNeeded);
  }

  SUBCASE(
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

    CHECK_EQ(TC_AWAIT(core2->start(identity)),
             Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(verificationKey)),
        Errc::InvalidVerification);
    REQUIRE_EQ(core2->status(), Status::IdentityVerificationNeeded);
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
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {Passphrase{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
  }

  SUBCASE("it gets verification methods before verifying identity")
  {
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
  }

  SUBCASE("it sets an email and adds a new device")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(
        core2->verifyIdentity(Verification::ByEmail{email, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {email}));
  }

  SUBCASE("it sets a phone number and adds a new device")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {phoneNumber}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(
        Verification::ByPhoneNumber{phoneNumber, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {phoneNumber}));
  }

  SUBCASE("it updates a verification passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    auto const newPassphrase = Passphrase{"new passphrase"};
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{newPassphrase})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(newPassphrase)));
  }

  SUBCASE("it sets a phone number and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumber, verificationCode}})));

    REQUIRE_NOTHROW(TC_AWAIT(
        core1->setVerificationMethod(Verification::Verification{passphrase})));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()),
                                 {phoneNumber, Passphrase{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()),
                                 {phoneNumber, Passphrase{}}));
  }

  SUBCASE("it sets an email and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    REQUIRE_NOTHROW(TC_AWAIT(
        core1->setVerificationMethod(Verification::Verification{passphrase})));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core1->getVerificationMethods()), {email, Passphrase{}}));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(checkVerificationMethods(
        TC_AWAIT(core2->getVerificationMethods()), {email, Passphrase{}}));
  }

  SUBCASE(
      "it fails to set a verification method after using a verification key")
  {
    auto const verificationKey = TC_AWAIT(core1->generateVerificationKey());
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{verificationKey})));

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->setVerificationMethod(
                                      Verification::Verification{passphrase})),
                                  Errc::PreconditionFailed);
  }

  SUBCASE("it fails to set a verification key after a verification method ")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Passphrase{"new passphrase"}})));

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->generateVerificationKey()),
                                  Errc::PreconditionFailed);
  }

  SUBCASE("it throws when trying to verify with an invalid passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(
        core1->registerIdentity(Verification::Verification{passphrase})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(Passphrase{"wrongPass"})),
        Errc::InvalidVerification);
    REQUIRE_EQ(core2->status(), Status::IdentityVerificationNeeded);
  }

  SUBCASE("it throws when trying to verify with an invalid verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(
            Verification::ByEmail{email, VerificationCode{"d3JvbmcK"}})),
        Errc::InvalidVerification);
    REQUIRE_EQ(core2->status(), Status::IdentityVerificationNeeded);
  }

  SUBCASE(
      "it fails to unlock after trying too many times with an invalid "
      "verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{
        Verification::ByEmail{email, verificationCode}})));

    auto const code = TC_AWAIT(getVerificationCode(email));

    REQUIRE_EQ(TC_AWAIT(core2->start(alice.identity)),
               Status::IdentityVerificationNeeded);
    for (int i = 0; i < 3; ++i)
    {
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(core2->verifyIdentity(
              Verification::ByEmail{email, VerificationCode{"d3JvbmcK"}})),
          Errc::InvalidVerification);
      REQUIRE_EQ(core2->status(), Status::IdentityVerificationNeeded);
    }
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(
            Verification::Verification{Verification::ByEmail{email, code}})),
        Errc::TooManyAttempts);
    REQUIRE_EQ(core2->status(), Status::IdentityVerificationNeeded);
  }

  SUBCASE("it throws when trying to verify before registration")
  {
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->verifyIdentity(passphrase)),
                                  Errc::PreconditionFailed);
    REQUIRE_EQ(core1->status(), Status::IdentityRegistrationNeeded);
  }

  SUBCASE("It updates email verification method on setVerificationMethods")
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

  SUBCASE(
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
}

TEST_CASE_FIXTURE(TrustchainFixture, "Verification through oidc")
{
  TC_AWAIT(enableOidc());

  auto martine = trustchain.makeUser();
  auto martineDevice = martine.makeDevice();
  auto martineLaptop = martineDevice.createCore();
  REQUIRE_EQ(TC_AWAIT(martineLaptop->start(martine.identity)),
             Status::IdentityRegistrationNeeded);

  auto martineDevice2 = martine.makeDevice();
  auto martinePhone = martineDevice2.createCore();

  auto oidcConfig = TestConstants::oidcConfig();

  OidcIdToken martineIdToken, kevinIdToken;
  {
    martineIdToken = TC_AWAIT(getOidcToken(oidcConfig, "martine"));
    kevinIdToken = TC_AWAIT(getOidcToken(oidcConfig, "kevin"));
  }

  SUBCASE("")
  {
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(martineIdToken)));

    SUBCASE("registers and verifies identity with an oidc id token")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          expectVerification(martinePhone, martine.identity, martineIdToken)));
    }
    SUBCASE("fails to verify a token with incorrect signature")
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
    SUBCASE("fails to verify a valid token for the wrong user")
    {
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(
              expectVerification(martinePhone, martine.identity, kevinIdToken)),
          Errc::InvalidVerification);
    }
  }
  SUBCASE("")
  {
    auto const pass = Passphrase{"******"};
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(pass)));

    SUBCASE("updates and verifies with an oidc token")
    {
      REQUIRE_NOTHROW(
          TC_AWAIT(martineLaptop->setVerificationMethod(martineIdToken)));
      REQUIRE_EQ(TC_AWAIT(martinePhone->start(martine.identity)),
                 Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(TC_AWAIT(martinePhone->verifyIdentity(martineIdToken)));
      REQUIRE_NOTHROW(checkVerificationMethods(
          TC_AWAIT(martinePhone->getVerificationMethods()),
          {Passphrase{}, OidcIdToken{}}));
    }
    SUBCASE(
        "fails to attach a provisional identity for the wrong google account")
    {
      auto const email = Email{"the-ceo@tanker.io"};
      auto const martineProvisionalIdentity =
          Identity::createProvisionalIdentity(
              mgs::base64::encode(trustchain.id), email);
      auto const result = TC_AWAIT(martineLaptop->attachProvisionalIdentity(
          SSecretProvisionalIdentity{martineProvisionalIdentity}));
      REQUIRE_EQ(result.status, Tanker::Status::IdentityVerificationNeeded);
      REQUIRE_EQ(result.verificationMethod, email);
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(martineLaptop->verifyProvisionalIdentity(martineIdToken)),
          Errc::InvalidArgument);
    }
    SUBCASE("decrypts data shared with an attached provisional identity")
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
      REQUIRE_EQ(result.status, Tanker::Status::IdentityVerificationNeeded);
      REQUIRE_EQ(result.verificationMethod, martineEmail);
      TC_AWAIT(martineLaptop->verifyProvisionalIdentity(martineIdToken));
      auto const decrypted = TC_AWAIT(martineLaptop->decrypt(encrypted));
      REQUIRE_EQ(clearText, decrypted);
    }
  }
}
