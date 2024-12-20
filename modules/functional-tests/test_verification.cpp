#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Format/StringView.hpp>
#include <Tanker/Functional/Provisional.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Config.hpp>
#include <Helpers/Email.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/PhoneNumber.hpp>

#include <mgs/base64url.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/variant2/variant.hpp>

#include "CheckDecrypt.hpp"
#include "HttpHelpers.hpp"
#include "OidcHelpers.hpp"

#include "TestSuite.hpp"

#include <string>

using namespace Tanker;
using namespace Tanker::Errors;
using Tanker::Functional::TrustchainFixture;

namespace
{
void checkVerificationMethods(std::vector<Verification::VerificationMethod> actual,
                              std::vector<Verification::VerificationMethod> expected)
{
  std::sort(actual.begin(), actual.end());
  std::sort(expected.begin(), expected.end());
  if (actual != expected)
    throw std::runtime_error("check failed: verification methods do not match");
}

tc::cotask<Tanker::Status> expectVerification(Functional::AsyncCorePtr session,
                                              std::string const& identity,
                                              Verification::Verification const& verification)
{
  REQUIRE(TC_AWAIT(session->start(identity)) == Status::IdentityVerificationNeeded);
  TC_AWAIT(session->verifyIdentity(verification));

  auto expected = Verification::VerificationMethod::from(verification);
  if (auto const oidc = boost::variant2::get_if<OidcIdToken>(&verification))
  {
    auto const& oidcConf = TestConstants::oidcConfig();
    expected = OidcIdToken{
        {},
        oidcProviderId(session->sdkInfo().trustchainId, oidcConf.issuer, oidcConf.clientId),
        oidcConf.displayName,
    };
  }

  checkVerificationMethods(TC_AWAIT(session->getVerificationMethods()), {expected});
  TC_RETURN(session->status());
}

OidcIdToken alterOidcTokenSignature(OidcIdToken const& idToken)
{
  namespace ba = boost::algorithm;
  using b64 = mgs::base64url_nopad;

  std::vector<std::string> res;
  auto itSig = ba::split(res, idToken.token, ba::is_any_of(".")).rbegin();
  auto alterSig = b64::decode(*itSig);
  ++alterSig[5];
  *itSig = b64::encode(alterSig);
  return OidcIdToken{ba::join(res, "."), {}, {}};
}

Verification::Verification createPAEPVerification(std::string password)
{
    auto const passphrasePublicEncryptionKey = TestConstants::passphrasePublicEncryptionKey();
    std::string paep = mgs::base64::encode(Crypto::prehashAndEncryptPassword(password, passphrasePublicEncryptionKey));
    return Verification::Verification{PrehashedAndEncryptedPassphrase{paep}};
}
}

TEST_CASE_METHOD(TrustchainFixture, "Verification")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE(TC_AWAIT(core1->start(alice.identity)) == Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const passphrase = Passphrase{"my passphrase"};
  auto const email = makeEmail();
  auto const phoneNumber = makePhoneNumber();

  SECTION("registerIdentity throws if passphrase is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(Passphrase{""})), Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if email is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(Verification::ByEmail{Email{""}, VerificationCode{"12345678"}})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if phone number is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core1->registerIdentity(Verification::ByPhoneNumber{PhoneNumber{""}, VerificationCode{"12345678"}})),
        Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if verificationCode is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(Verification::ByEmail{email, VerificationCode{""}})),
                                  Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if OidcIdToken is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(OidcIdToken{"", {}, {}})), Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("registerIdentity throws if verificationKey is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(VerificationKey{""})), Errc::InvalidVerification);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "registerIdentity throws adequate exception when verificationKey public "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    auto ghostDevice = nlohmann::json::parse(mgs::base64::decode(verificationKey)).get<GhostDevice>();
    // Corrupt the public signature key
    ghostDevice.privateSignatureKey[2]++;
    verificationKey = VerificationKey{mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(verificationKey)), Errc::InvalidVerification);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "registerIdentity throws adequate exception when verificationKey private "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    auto ghostDevice = nlohmann::json::parse(mgs::base64::decode(verificationKey)).get<GhostDevice>();
    // Corrupt the private signature key
    ghostDevice.privateSignatureKey[60]++;
    verificationKey = VerificationKey{mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(verificationKey)), Errc::InvalidVerification);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "verify identity throws adequate exceptions when verificationKey public "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice = nlohmann::json::parse(mgs::base64::decode(verificationKey)).get<GhostDevice>();
    // Corrupt the public signature key
    ghostDevice.privateSignatureKey[2]++;
    verificationKey = VerificationKey{mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(mgs::base64::decode(alice.identity)).get<Identity::SecretPermanentIdentity>();
    auto identity = mgs::base64::encode(nlohmann::ordered_json(aliceIdentity).dump());

    CHECK(TC_AWAIT(core2->start(identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(verificationKey)), Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "verify identity throws adequate exceptions when verificationKey private "
      "signature key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice = nlohmann::json::parse(mgs::base64::decode(verificationKey)).get<GhostDevice>();
    // Corrupt the private signature key
    ghostDevice.privateSignatureKey[60]++;
    verificationKey = VerificationKey{mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(mgs::base64::decode(alice.identity)).get<Identity::SecretPermanentIdentity>();
    auto identity = mgs::base64::encode(nlohmann::ordered_json(aliceIdentity).dump());

    CHECK(TC_AWAIT(core2->start(identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(verificationKey)), Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "verify identity throws adequate exceptions when verificationKey private "
      "encryption key is corrupted")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    auto ghostDevice = nlohmann::json::parse(mgs::base64::decode(verificationKey)).get<GhostDevice>();
    // Corrupt the private encryption key
    ghostDevice.privateEncryptionKey[2]++;
    verificationKey = VerificationKey{mgs::base64::encode(nlohmann::json(ghostDevice).dump())};

    auto aliceIdentity =
        nlohmann::json::parse(mgs::base64::decode(alice.identity)).get<Identity::SecretPermanentIdentity>();
    auto identity = mgs::base64::encode(nlohmann::ordered_json(aliceIdentity).dump());

    CHECK(TC_AWAIT(core2->start(identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(verificationKey)), Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("it creates an verificationKey and use it to add a second device")
  {
    auto verificationKey = TC_AWAIT(core1->generateVerificationKey());
    TC_AWAIT(core1->registerIdentity(verificationKey));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {VerificationKey{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(verificationKey)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {VerificationKey{}}));
  }

  SECTION("it sets a passphrase and adds a new device")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{passphrase})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {Passphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
  }

  SECTION("it gets verification methods before verifying identity")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{passphrase})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {Passphrase{}}));
  }

  SECTION("it sets an email and adds a new device")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {email}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(Verification::ByEmail{email, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {email}));
  }

  SECTION("it sets a phone number and adds a new device")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {phoneNumber}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(Verification::ByPhoneNumber{phoneNumber, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {phoneNumber}));
  }

  SECTION("it updates a verification passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{passphrase})));

    auto const newPassphrase = Passphrase{"new passphrase"};
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(Verification::Verification{newPassphrase})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(newPassphrase)));
  }

  SECTION("it sets a phone number and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}})));

    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(Verification::Verification{passphrase})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {phoneNumber, Passphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {phoneNumber, Passphrase{}}));
  }

  SECTION("it sets an email and then sets a passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(Verification::Verification{passphrase})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {email, Passphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(passphrase)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {email, Passphrase{}}));
  }

  SECTION("it fails to set a verification method after using a verification key")
  {
    auto const verificationKey = TC_AWAIT(core1->generateVerificationKey());
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{verificationKey})));

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->setVerificationMethod(Verification::Verification{passphrase})),
                                  Errc::PreconditionFailed);
  }

  SECTION("it fails to set a verification key after a verification method ")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{Passphrase{"new passphrase"}})));

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->generateVerificationKey()), Errc::PreconditionFailed);
  }

  SECTION("it throws when trying to verify with an invalid passphrase [KHWR1T]")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{passphrase})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(Passphrase{"wrongPass"})), Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("it throws when trying to verify with an invalid verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    auto const code = TC_AWAIT(getVerificationCode(email));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(Verification::ByEmail{email, VerificationCode{"00000000"}})),
        Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "it fails to unlock after trying too many times with an invalid "
      "verification code")
  {
    auto const verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    auto const code = TC_AWAIT(getVerificationCode(email));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    for (int i = 0; i < 3; ++i)
    {
      TANKER_CHECK_THROWS_WITH_CODE(
          TC_AWAIT(core2->verifyIdentity(Verification::ByEmail{email, VerificationCode{"00000000"}})),
          Errc::InvalidVerification);
      REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
    }
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(core2->verifyIdentity(Verification::Verification{Verification::ByEmail{email, code}})),
        Errc::TooManyAttempts);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("it throws when trying to verify before registration")
  {
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->verifyIdentity(passphrase)), Errc::PreconditionFailed);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("It updates email verification method on setVerificationMethods")
  {
    // register
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}}));

    // update email
    auto const newEmail = makeEmail();
    verificationCode = TC_AWAIT(getVerificationCode(newEmail));
    TC_AWAIT(
        core1->setVerificationMethod(Verification::Verification{Verification::ByEmail{newEmail, verificationCode}}));

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

  SECTION("It updates phone number verification method on setVerificationMethods")
  {
    // register
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    // update phone number
    auto const newPhoneNumber = makePhoneNumber();
    verificationCode = TC_AWAIT(getVerificationCode(newPhoneNumber));
    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{Verification::ByPhoneNumber{newPhoneNumber, verificationCode}}));

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

TEST_CASE_METHOD(TrustchainFixture, "Verification with preverified email")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE(TC_AWAIT(core1->start(alice.identity)) == Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const email = makeEmail();
  auto const phoneNumber = makePhoneNumber();

  auto const preverifiedEmail = PreverifiedEmail{"superkirby@tanker.io"};
  auto const emailOfPreverifiedEmail = Email{preverifiedEmail.string()};

  SECTION("registerIdentity throws when verification method is preverified email")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(preverifiedEmail)), Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("verifyIdentity throws when verification method is preverified email")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(preverifiedEmail)), Errc::InvalidArgument);

    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "it registers with an email, updates to preverified email when calling "
      "setVerificationMethod, and updates to normal email when verifying")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedEmail}));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {preverifiedEmail}));

    TC_AWAIT(core2->start(alice.identity));
    verificationCode = TC_AWAIT(getVerificationCode(emailOfPreverifiedEmail));
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(Verification::ByEmail{emailOfPreverifiedEmail, verificationCode})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {emailOfPreverifiedEmail}));
  }

  SECTION(
      "it register with an email, updates to preverified email when calling "
      "setVerificationMethod with the same email")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}}));

    auto const newPreverifiedEmail = PreverifiedEmail{"kirby@tanker.io"};
    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{newPreverifiedEmail}));

    // check that email is ok
    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {newPreverifiedEmail}));
  }

  SECTION(
      "It turns preverified email method into email method when calling "
      "setVerificationMethod")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedEmail}));

    verificationCode = TC_AWAIT(getVerificationCode(emailOfPreverifiedEmail));
    TC_AWAIT(core1->setVerificationMethod(
        Verification::Verification{Verification::ByEmail{emailOfPreverifiedEmail, verificationCode}}));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {emailOfPreverifiedEmail}));
  }

  SECTION(
      "it turns preverified email method into email method when calling "
      "verifyProvisionalIdentity")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedEmail}));

    auto const secretProvisionalIdentity = SSecretProvisionalIdentity(
        Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), emailOfPreverifiedEmail));
    auto const publicProvisionalIdentity =
        SPublicIdentity(Identity::getPublicIdentity(secretProvisionalIdentity.string()));

    auto const aliceProvisional =
        Functional::AppProvisionalUser{emailOfPreverifiedEmail, secretProvisionalIdentity, publicProvisionalIdentity};

    REQUIRE_NOTHROW(TC_AWAIT(attachProvisionalIdentity(*core1, aliceProvisional)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {emailOfPreverifiedEmail}));
  }

  SECTION("It adds preverified email as a new verification method")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedEmail}));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {phoneNumber, preverifiedEmail}));
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification with E2E passphrase")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE(TC_AWAIT(core1->start(alice.identity)) == Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const passphrase = Passphrase{"average passphrase"};
  auto const e2ePassphrase = E2ePassphrase{"Correct horse battery staple"};

  SECTION("registerIdentity throws if e2e passphrase is empty")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(E2ePassphrase{""})), Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("it sets an E2E passphrase and adds a new device")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{e2ePassphrase})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {E2ePassphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(e2ePassphrase)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {E2ePassphrase{}}));
  }

  SECTION("it throws when trying to verify with an invalid E2E passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Verification::Verification{e2ePassphrase})));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(E2ePassphrase{"wrongPass"})),
                                  Errc::InvalidVerification);
    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "it can't switch to an e2e passphrase without setting "
      "the allowE2eMethodSwitch flag")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(passphrase)));
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->setVerificationMethod(e2ePassphrase)), Errc::InvalidArgument);
  }

  SECTION(
      "it can't switch from an e2e passphrase without setting "
      "the allowE2eMethodSwitch flag")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(e2ePassphrase)));
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->setVerificationMethod(passphrase)), Errc::InvalidArgument);
  }

  SECTION("it erases previous methods when switching to an e2e passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(passphrase)));
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
        e2ePassphrase, Tanker::Core::VerifyWithToken::No, Tanker::Core::AllowE2eMethodSwitch::Yes)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {E2ePassphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(passphrase)), Errc::PreconditionFailed);
  }

  SECTION("it erases previous methods when switching from an e2e passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(e2ePassphrase)));
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
        passphrase, Tanker::Core::VerifyWithToken::No, Tanker::Core::AllowE2eMethodSwitch::Yes)));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {Passphrase{}}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(e2ePassphrase)), Errc::PreconditionFailed);
  }

  SECTION(
      "it can switch several times back and forth before setting an e2e "
      "passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(core1->registerIdentity(Passphrase{"one"})));
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
        E2ePassphrase{"two"}, Tanker::Core::VerifyWithToken::No, Tanker::Core::AllowE2eMethodSwitch::Yes)));
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(E2ePassphrase{"three"})));
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
        Passphrase{"four"}, Tanker::Core::VerifyWithToken::No, Tanker::Core::AllowE2eMethodSwitch::Yes)));
    REQUIRE_NOTHROW(TC_AWAIT(core1->setVerificationMethod(
        E2ePassphrase{"fifth"}, Tanker::Core::VerifyWithToken::No, Tanker::Core::AllowE2eMethodSwitch::Yes)));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(core2->verifyIdentity(E2ePassphrase{"fifth"})));
    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core2->getVerificationMethods()), {E2ePassphrase{}}));
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification with preverified phone number")
{
  auto alice = trustchain.makeUser();
  auto device1 = alice.makeDevice();
  auto core1 = device1.createCore();
  REQUIRE(TC_AWAIT(core1->start(alice.identity)) == Status::IdentityRegistrationNeeded);

  auto device2 = alice.makeDevice();
  auto core2 = device2.createCore();

  auto const email = makeEmail();
  auto const phoneNumber = makePhoneNumber();

  auto const preverifiedPhoneNumber = PreverifiedPhoneNumber{"+33639982244"};
  auto const phoneNumberOfPreverifiedPhoneNumber = PhoneNumber{preverifiedPhoneNumber.string()};

  SECTION(
      "registerIdentity throws when verification method is preverified phone "
      "number")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core1->registerIdentity(PreverifiedPhoneNumber{preverifiedPhoneNumber})),
                                  Errc::InvalidArgument);
    REQUIRE(core1->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION(
      "verifyIdentity throws when verification method is preverified phone "
      "number")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(
        TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {email}));

    REQUIRE(TC_AWAIT(core2->start(alice.identity)) == Status::IdentityVerificationNeeded);

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->verifyIdentity(PreverifiedPhoneNumber{preverifiedPhoneNumber})),
                                  Errc::InvalidArgument);

    REQUIRE(core2->status() == Status::IdentityVerificationNeeded);
  }

  SECTION(
      "it registers with a phone number, updates to preverified phone number "
      "when calling setVerificationMethod, and updates to normal phone number "
      "when verifying")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedPhoneNumber}));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {preverifiedPhoneNumber}));

    TC_AWAIT(core2->start(alice.identity));
    verificationCode = TC_AWAIT(getVerificationCode(phoneNumberOfPreverifiedPhoneNumber));
    REQUIRE_NOTHROW(TC_AWAIT(
        core2->verifyIdentity(Verification::ByPhoneNumber{phoneNumberOfPreverifiedPhoneNumber, verificationCode})));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {phoneNumberOfPreverifiedPhoneNumber}));
  }

  SECTION(
      "register with a phone number, updates to preverified phone number when "
      "calling setVerificationMethod with the same phone number")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    auto const newPreverifiedPhoneNumber = PreverifiedPhoneNumber{phoneNumber.string()};
    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{newPreverifiedPhoneNumber}));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {newPreverifiedPhoneNumber}));
  }

  SECTION(
      "It turns preverified phone number method into phone number method when "
      "calling setVerificationMethod")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedPhoneNumber}));

    verificationCode = TC_AWAIT(getVerificationCode(phoneNumberOfPreverifiedPhoneNumber));
    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{
        Verification::ByPhoneNumber{phoneNumberOfPreverifiedPhoneNumber, verificationCode}}));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {phoneNumberOfPreverifiedPhoneNumber}));
  }

  SECTION(
      "it turns preverified phone number method into phone number method when "
      "calling verifyProvisionalIdentity")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(phoneNumber));
    TC_AWAIT(core1->registerIdentity(
        Verification::Verification{Verification::ByPhoneNumber{phoneNumber, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedPhoneNumber}));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {preverifiedPhoneNumber}));

    auto const secretProvisionalIdentity = SSecretProvisionalIdentity(
        Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), phoneNumberOfPreverifiedPhoneNumber));
    auto const publicProvisionalIdentity =
        SPublicIdentity(Identity::getPublicIdentity(secretProvisionalIdentity.string()));

    auto const aliceProvisional = Functional::AppProvisionalUser{
        phoneNumberOfPreverifiedPhoneNumber, secretProvisionalIdentity, publicProvisionalIdentity};

    REQUIRE_NOTHROW(TC_AWAIT(attachProvisionalIdentity(*core1, aliceProvisional)));

    CHECK_NOTHROW(
        checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {phoneNumberOfPreverifiedPhoneNumber}));
  }

  SECTION("It adds preverified phone number as a new verification method")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    TC_AWAIT(core1->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}}));

    TC_AWAIT(core1->setVerificationMethod(Verification::Verification{preverifiedPhoneNumber}));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(core1->getVerificationMethods()), {email, preverifiedPhoneNumber}));
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification through oidc")
{
  auto martine = trustchain.makeUser();
  auto martineDevice = martine.makeDevice();
  auto martineLaptop = martineDevice.createCore();
  REQUIRE(TC_AWAIT(martineLaptop->start(martine.identity)) == Status::IdentityRegistrationNeeded);

  auto martineDevice2 = martine.makeDevice();
  auto martinePhone = martineDevice2.createCore();

  SECTION("with Google Oidc provider")
  {
    TC_AWAIT(enableOidc());
    auto const oidcConfig = TestConstants::oidcConfig();
    auto const martineIdToken = TC_AWAIT(getOidcToken(oidcConfig, "martine"));
    auto const kevinIdToken = TC_AWAIT(getOidcToken(oidcConfig, "kevin"));

    SECTION("registers with an oidc id token")
    {
      auto const testNonce = TC_AWAIT(martineLaptop->createOidcNonce());
      martineLaptop->setOidcTestNonce(testNonce);
      REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(martineIdToken)));
    }

    SECTION("")
    {
      auto const testNonce = TC_AWAIT(martineLaptop->createOidcNonce());
      martineLaptop->setOidcTestNonce(testNonce);
      TC_AWAIT(martineLaptop->registerIdentity(martineIdToken));

      SECTION("verifies identity with an oidc id token")
      {
        auto const testNonce = TC_AWAIT(martinePhone->createOidcNonce());
        martinePhone->setOidcTestNonce(testNonce);
        REQUIRE_NOTHROW(TC_AWAIT(expectVerification(martinePhone, martine.identity, martineIdToken)));
      }

      SECTION("fails to verify a token with incorrect signature")
      {
        auto const alteredToken = alterOidcTokenSignature(martineIdToken);

        auto const testNonce = TC_AWAIT(martinePhone->createOidcNonce());
        martinePhone->setOidcTestNonce(testNonce);
        TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(expectVerification(martinePhone, martine.identity, alteredToken)),
                                      Errc::InvalidVerification);
      }

      SECTION("fails to verify a valid token for the wrong user")
      {
        auto const testNonce = TC_AWAIT(martinePhone->createOidcNonce());
        martinePhone->setOidcTestNonce(testNonce);
        TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(expectVerification(martinePhone, martine.identity, kevinIdToken)),
                                      Errc::InvalidVerification);
      }
    }

    SECTION("")
    {
      auto const pass = Passphrase{"******"};
      REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(pass)));

      SECTION("updates and verifies with an oidc token")
      {
        auto testNonce = TC_AWAIT(martineLaptop->createOidcNonce());
        martineLaptop->setOidcTestNonce(testNonce);
        REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->setVerificationMethod(martineIdToken)));
        REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) == Status::IdentityVerificationNeeded);
        testNonce = TC_AWAIT(martinePhone->createOidcNonce());
        martinePhone->setOidcTestNonce(testNonce);
        REQUIRE_NOTHROW(TC_AWAIT(martinePhone->verifyIdentity(martineIdToken)));

        auto expectedOidc = OidcIdToken{
            {},
            oidcProviderId(martinePhone->sdkInfo().trustchainId, oidcConfig.issuer, oidcConfig.clientId),
            oidcConfig.displayName,
        };
        REQUIRE_NOTHROW(
            checkVerificationMethods(TC_AWAIT(martinePhone->getVerificationMethods()), {Passphrase{}, expectedOidc}));
      }
      SECTION("fails to attach a provisional identity using OIDC")
      {
        auto const email = makeEmail();
        auto const martineProvisionalIdentity =
            Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), email);
        auto const result =
            TC_AWAIT(martineLaptop->attachProvisionalIdentity(SSecretProvisionalIdentity{martineProvisionalIdentity}));
        REQUIRE(result.status == Tanker::Status::IdentityVerificationNeeded);
        REQUIRE(result.verificationMethod == email);
        auto const testNonce = TC_AWAIT(martineLaptop->createOidcNonce());
        martinePhone->setOidcTestNonce(testNonce);
        TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martineLaptop->verifyProvisionalIdentity(martineIdToken)),
                                      Errc::InvalidArgument);
      }
    }
  }

  SECTION("with Pro Sante Connect")
  {
    // This token was generated by the DOMAK team
    // Other tokens like this are used in the monolith's tests here:
    // doctolib/doctolib/test/fixtures/configuration/profile/*.json
    // Field name where the tokens are `credentials.id_token`
    auto const pscIdToken = OidcIdToken{
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJKRlRBM1llVVdQbERCTE"
        "JfeU5qWUs0bWZJcTdhYXBBS21ieVdyczRPZ0RnIn0."
        "eyJleHAiOjE2NjU1Nzk5NjgsImlhdCI6MTY2NTU3OTg0OCwiYXV0aF90aW1lIjoxNjY1NT"
        "c5NDkyLCJqdGkiOiI4NTI4MzIwNi01ZmQyLTQ0YjQtYWI4NS0yZWI1ODA2ZWIwMzQiLCJp"
        "c3MiOiJodHRwczovL2F1dGguYmFzLnBzYy5lc2FudGUuZ291di5mci9hdXRoL3JlYWxtcy"
        "9lc2FudGUtd2FsbGV0IiwiYXVkIjoiZG9jdG9saWItZGV2Iiwic3ViIjoiZjo1NTBkYzFj"
        "OC1kOTdiLTRiMWUtYWM4Yy04ZWI0NDcxY2Y5ZGQ6QU5TMjAyMjAyMTUxODM5MzIiLCJ0eX"
        "AiOiJJRCIsImF6cCI6ImRvY3RvbGliLWRldiIsIm5vbmNlIjoibzVWUHh0WlY0bl8wRXBx"
        "R2h0UGduYXd6T3lRY1VQWmk4b1RjNjJWajNkSSIsInNlc3Npb25fc3RhdGUiOiIwNDRiOW"
        "MzNS0xZDhmLTQ5MjUtOGFlOC0yMmNmNTg1ZTA3OWMiLCJhdF9oYXNoIjoibVV0bkp2V3d0"
        "VHRQMkFDSDR2RElBUSIsInNpZCI6IjA0NGI5YzM1LTFkOGYtNDkyNS04YWU4LTIyY2Y1OD"
        "VlMDc5YyIsImF1dGhNb2RlIjoiTU9CSUxFIiwiYWNyIjoiZWlkYXMxIiwiU3ViamVjdE5h"
        "bWVJRCI6IkFOUzIwMjIwMjE1MTgzOTMyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQU5TMj"
        "AyMjAyMTUxODM5MzIiLCJnaXZlbl9uYW1lIjoiR3VpbGxhdW1lIiwiZmFtaWx5X25hbWUi"
        "OiJGYXlhcmQifQ.l272gvwOt5aVXiG4F7ZCpQVqWByQ_"
        "DvQpuJPMR50TVqtAy76kdngHKgiNEg7CIe6UkMGsqcXMvrm0ihROTp3OWpwnaS2LityoE_"
        "Kv32HMNgHazsOS19snlBz8TbV3MkpW5JFkdjLVdFVVqxDqkZzozKxpqIvbumPQBl100bEt"
        "wakMw4em-8Hk69wi6jQNsVADRSslpHVSyYhHXwMX8l-"
        "yhR965nyxIETVlIHbwKvpyy05a3B0GmmCReZT4UnCPA4eqFUw5VL9GwKXl0Ok46ZKMp742"
        "qW6oytC7V4KIc01ErcoQ_D4EwM6rBWgZcqaDxUazcCTlZUEAlS7wXXw6UXWQ",
        {},
        {}};

    SECTION("rejects expired token on pro-sante-bas")
    {
      TC_AWAIT(enablePSCOidc(PSCProvider::PSC_BAS));

      auto const testNonce = TC_AWAIT(martinePhone->createOidcNonce());
      martinePhone->setOidcTestNonce(testNonce);

      TC_AWAIT(martinePhone->start(martine.identity));
      TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martinePhone->registerIdentity(pscIdToken)), Errc::InvalidVerification);
    }

    SECTION("accepts expired token on pro-sante-bas-no-expiry")
    {
      TC_AWAIT(enablePSCOidc(PSCProvider::PSC_BAS_NO_EXPIRY));

      auto const testNonce = TC_AWAIT(martinePhone->createOidcNonce());
      TC_AWAIT(martinePhone->start(martine.identity));
      martinePhone->setOidcTestNonce(testNonce);
      REQUIRE_NOTHROW(TC_AWAIT(martinePhone->registerIdentity(pscIdToken)));
    }
  }
}

TEST_CASE_METHOD(TrustchainFixture, "authenticateWithIdp is restricted to trusted OIDC providers")
{
  auto martine = trustchain.makeUser();
  auto martineDevice = martine.makeDevice();
  auto martineLaptop = martineDevice.createCore();

  TC_AWAIT(enableOidc());
  auto const googleOidcConfig = TestConstants::oidcConfig();
  auto const providerId = oidcProviderId(martineLaptop->sdkInfo().trustchainId, googleOidcConfig.issuer, googleOidcConfig.clientId);

  REQUIRE(TC_AWAIT(martineLaptop->start(martine.identity)) == Status::IdentityRegistrationNeeded);
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, "fake_oidc_subject=martine")),
                                Errc::PreconditionFailed);
}

TEST_CASE_METHOD(TrustchainFixture, "verification by oidc authorization code")
{
  auto martine = trustchain.makeUser();
  auto martineDevice = martine.makeDevice();
  auto martineLaptop = martineDevice.createCore();
  auto martineDevice2 = martine.makeDevice();
  auto martinePhone = martineDevice2.createCore();

  auto const subjectCookie = "fake_oidc_subject=martine";
  auto const fakeOidcIssuerUrl = TestConstants::oidcConfig().fakeOidcIssuerUrl;
  auto const providerId =
      oidcProviderId(martineLaptop->sdkInfo().trustchainId, fakeOidcIssuerUrl + "/main", "tanker");

  TC_AWAIT(enableFakeOidc());

  REQUIRE(TC_AWAIT(martineLaptop->start(martine.identity)) == Status::IdentityRegistrationNeeded);

  SECTION("registers and verifies with an oidc authorization code")
  {
    auto const verification1 = TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, subjectCookie));
    auto const verification2 = TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, subjectCookie));

    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(verification1)));

    REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) == Status::IdentityVerificationNeeded);
    REQUIRE_NOTHROW(TC_AWAIT(martinePhone->verifyIdentity(verification2)));
    REQUIRE(martinePhone->status() == Status::Ready);
  }

  SECTION("fails to verify an oidc authorization code twice")
  {
    auto const verification = TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, subjectCookie));
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(verification)));

    REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martinePhone->verifyIdentity(verification)), Errc::InvalidVerification);
  }

  SECTION("fails to verify an oidc authorization code for the wrong user")
  {
    auto const verification1 = TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, subjectCookie));

    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(verification1)));

    auto const verification2 =
        TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, "fake_oidc_subject=not-martine"));
    REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martinePhone->verifyIdentity(verification2)), Errc::InvalidVerification);
  }

  SECTION("updates and verifies with an oidc authorization code")
  {
    auto const pass = Passphrase{"******"};
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(pass)));
    auto const verification1 = TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, subjectCookie));
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->setVerificationMethod(verification1)));

    REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) == Status::IdentityVerificationNeeded);
    auto const verification2 = TC_AWAIT(martinePhone->authenticateWithIdp(providerId, subjectCookie));
    REQUIRE_NOTHROW(TC_AWAIT(martinePhone->verifyIdentity(verification2)));
    REQUIRE(martinePhone->status() == Status::Ready);
  }

  SECTION("registers and verifies with different oidc providers from the same provider group")
  {
    TC_AWAIT(enableFakeOidc());
    auto const altProviderId =
        oidcProviderId(martineLaptop->sdkInfo().trustchainId, fakeOidcIssuerUrl + "/alt", "tanker");
    auto const wrongProviderId =
        oidcProviderId(martineLaptop->sdkInfo().trustchainId, fakeOidcIssuerUrl + "/wrong-group", "tanker");

    auto const verification1 = TC_AWAIT(martineLaptop->authenticateWithIdp(providerId, subjectCookie));
    auto const verification2 = TC_AWAIT(martineLaptop->authenticateWithIdp(wrongProviderId, subjectCookie));
    auto const verification3 = TC_AWAIT(martineLaptop->authenticateWithIdp(altProviderId, subjectCookie));

    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(verification1)));

    REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) == Status::IdentityVerificationNeeded);
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martinePhone->verifyIdentity(verification2)), Errc::PreconditionFailed);

    REQUIRE_NOTHROW(TC_AWAIT(martinePhone->verifyIdentity(verification3)));
    REQUIRE(martinePhone->status() == Status::Ready);
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification with preverified oidc")
{
  auto martine = trustchain.makeUser();
  auto martineDevice = martine.makeDevice();
  auto martineLaptop = martineDevice.createCore();
  REQUIRE(TC_AWAIT(martineLaptop->start(martine.identity)) == Status::IdentityRegistrationNeeded);

  auto martineDevice2 = martine.makeDevice();
  auto martinePhone = martineDevice2.createCore();

  auto const email = makeEmail();
  auto providerID = "test";
  auto subject = "a subject";

  SECTION("registerIdentity throws when verification method is preverified oidc")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martineLaptop->registerIdentity(PreverifiedOidc{providerID, subject})),
                                  Errc::InvalidArgument);
    REQUIRE(martineLaptop->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("verifyIdentity throws when verification method is preverified oidc")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(
        martineLaptop->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(martineLaptop->getVerificationMethods()), {email}));

    REQUIRE(TC_AWAIT(martinePhone->start(alice.identity)) == Status::IdentityVerificationNeeded);

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(martinePhone->verifyIdentity(PreverifiedOidc{providerID, subject})),
                                  Errc::InvalidArgument);

    REQUIRE(martinePhone->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("setVerificationMethod adds preverified oidc as a new verification method")
  {
    TC_AWAIT(enableOidc());
    auto const oidcConfig = TestConstants::oidcConfig();
    auto const providerId =
        oidcProviderId(martinePhone->sdkInfo().trustchainId, oidcConfig.issuer, oidcConfig.clientId);
    auto const martineIdToken = TC_AWAIT(getOidcToken(oidcConfig, "martine"));
    auto const subject = getOidcSubject(martineIdToken);

    auto const pass = Passphrase{"******"};
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(pass)));
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->setVerificationMethod(PreverifiedOidc{providerId, subject})));

    REQUIRE(TC_AWAIT(martinePhone->start(martine.identity)) == Status::IdentityVerificationNeeded);
    auto testNonce = TC_AWAIT(martinePhone->createOidcNonce());
    martinePhone->setOidcTestNonce(testNonce);
    REQUIRE_NOTHROW(TC_AWAIT(martinePhone->verifyIdentity(martineIdToken)));

    auto expectedOidc = OidcIdToken{
        {},
        providerId,
        oidcConfig.displayName,
    };
    REQUIRE_NOTHROW(
        checkVerificationMethods(TC_AWAIT(martinePhone->getVerificationMethods()), {Passphrase{}, expectedOidc}));
  }

  SECTION("sets a verification method for every oidc provider from the same oidc provider group at once")
  {
    auto const fakeOidcIssuerUrl = TestConstants::oidcConfig().fakeOidcIssuerUrl;
    auto const mainProviderId =
        oidcProviderId(martineLaptop->sdkInfo().trustchainId, fakeOidcIssuerUrl + "/main", "tanker");
    auto const altProviderId =
        oidcProviderId(martineLaptop->sdkInfo().trustchainId, fakeOidcIssuerUrl + "/alt", "tanker");
    auto expectedMainOidc = OidcIdToken{
        {},
        mainProviderId,
        "fake-oidc",
    };
    auto expectedAltOidc = OidcIdToken{
        {},
        altProviderId,
        "fake-oidc/alt",
    };

    auto const pass = Passphrase{"******"};
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->registerIdentity(pass)));
    REQUIRE_NOTHROW(TC_AWAIT(martineLaptop->setVerificationMethod(PreverifiedOidc{mainProviderId, subject})));

    REQUIRE_NOTHROW(
        checkVerificationMethods(TC_AWAIT(martineLaptop->getVerificationMethods()), {Passphrase{}, expectedMainOidc, expectedAltOidc}));
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Verification with prehashed and encrypted passphrase")
{
  auto gerard = trustchain.makeUser();
  auto device1 = gerard.makeDevice();
  auto laptop = device1.createCore();
  auto device2 = gerard.makeDevice();
  auto phone = device2.createCore();

  REQUIRE(TC_AWAIT(laptop->start(gerard.identity)) == Status::IdentityRegistrationNeeded);

  auto const email = makeEmail();
  auto const prehashedAndEncryptedPassphraseVerification = createPAEPVerification("gErtruD");

  SECTION("registerIdentity throws when verification method is prehashed and encrypted passphrase")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(laptop->registerIdentity(prehashedAndEncryptedPassphraseVerification)),
                                  Errc::InvalidArgument);
    REQUIRE(laptop->status() == Status::IdentityRegistrationNeeded);
  }

  SECTION("verifyIdentity throws when verification method is prehashed and encrypted passphrase")
  {
    auto verificationCode = TC_AWAIT(getVerificationCode(email));
    REQUIRE_NOTHROW(TC_AWAIT(
        laptop->registerIdentity(Verification::Verification{Verification::ByEmail{email, verificationCode}})));

    CHECK_NOTHROW(checkVerificationMethods(TC_AWAIT(laptop->getVerificationMethods()), {email}));

    REQUIRE(TC_AWAIT(phone->start(gerard.identity)) == Status::IdentityVerificationNeeded);

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(phone->verifyIdentity(prehashedAndEncryptedPassphraseVerification)),
                                  Errc::InvalidArgument);

    REQUIRE(phone->status() == Status::IdentityVerificationNeeded);
  }

  SECTION("setVerificationMethod throws when verification method is prehashed and encrypted passphrase")
  {
    REQUIRE_NOTHROW(TC_AWAIT(laptop->registerIdentity(Passphrase{"******"})));
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(laptop->setVerificationMethod(prehashedAndEncryptedPassphraseVerification)),
                                  Errc::InvalidArgument);
  }
}

TEST_CASE_METHOD(TrustchainFixture, "User enrollment errors")
{
  TC_AWAIT(enableOidc());
  auto serverUser = trustchain.makeUser();
  auto sDevice = serverUser.makeDevice();
  auto server = sDevice.createCore();

  auto const oidcConfig = TestConstants::oidcConfig();
  auto const martineIdToken = TC_AWAIT(getOidcToken(oidcConfig, "martine"));

  auto const email = PreverifiedEmail{"kirby@tanker.io"};
  auto const emailVerification = Verification::Verification{email};
  auto const phoneNumber = PreverifiedPhoneNumber{"+33639982233"};
  auto const phoneNumberVerification = Verification::Verification{phoneNumber};
  auto const providerId = oidcProviderId(server->sdkInfo().trustchainId, oidcConfig.issuer, oidcConfig.clientId);
  auto const subject = getOidcSubject(martineIdToken);
  auto const oidcVerification = PreverifiedOidc{providerId, subject};
  auto const prehashedAndEncryptedPassphraseVerification = createPAEPVerification("Test:1-2-1-2");

  auto enrolledUser = trustchain.makeUser();

  SECTION("throws when tanker is not STOPPED")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->enrollUser(enrolledUser.identity, {emailVerification})),
                                  Errc::PreconditionFailed);
  }

  SECTION("throws when identity's trustchain does not match tanker's")
  {
    auto invalidIdentity = Identity::extract<Identity::SecretPermanentIdentity>(enrolledUser.identity);
    invalidIdentity.trustchainId[0]++;

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(server->enrollUser(to_string(invalidIdentity), {emailVerification})),
                                  Errc::InvalidArgument);
  }

  SECTION("throws when identity is valid but truncated")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(server->enrollUser(enrolledUser.identity.substr(0, enrolledUser.identity.length() - 10),
                                    {emailVerification})),
        Errc::InvalidArgument);
  }

  SECTION("throws when identity is not a permanent private identity")
  {
    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(server->enrollUser(enrolledUser.spublicIdentity().string(), {emailVerification})),
        Errc::InvalidArgument);
  }

  SECTION("throws when verifications are invalid")
  {
    std::vector<std::vector<Verification::Verification>> badPreverifiedVerifications{
        {},
        {Verification::ByEmail{Email(email.string()), ""}},
        {Verification::ByPhoneNumber{PhoneNumber(phoneNumber.string()), ""}},
        {PreverifiedOidc{providerId, ""}},
        {PreverifiedOidc{"", subject}},
        {emailVerification, Verification::Verification{Passphrase("********")}},
        {emailVerification, emailVerification},
        {phoneNumberVerification, phoneNumberVerification},
        {oidcVerification, oidcVerification},
        {prehashedAndEncryptedPassphraseVerification, prehashedAndEncryptedPassphraseVerification}
    };

    for (auto const& verifications : badPreverifiedVerifications)
    {
      TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(server->enrollUser(enrolledUser.identity, verifications)),
                                    Errc::InvalidArgument);
    }
  }

  SECTION("throws when enrolling a user multiple times")
  {
    REQUIRE_NOTHROW(TC_AWAIT(server->enrollUser(enrolledUser.identity, {phoneNumberVerification})));
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(server->enrollUser(enrolledUser.identity, {phoneNumberVerification})),
                                  Errc::Conflict);
  }

  SECTION("throws when enrolling a registered user")
  {
    auto const device = enrolledUser.makeDevice();
    auto const core = sDevice.createCore();

    REQUIRE_NOTHROW(TC_AWAIT(core->start(enrolledUser.identity)));
    auto const verifiedPhone = PhoneNumber(phoneNumber.string());
    REQUIRE_NOTHROW(TC_AWAIT(core->registerIdentity(
        Verification::ByPhoneNumber{verifiedPhone, TC_AWAIT(getVerificationCode(verifiedPhone))})));

    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(server->enrollUser(enrolledUser.identity, {phoneNumberVerification})),
                                  Errc::Conflict);
  }
}

TEST_CASE_METHOD(TrustchainFixture, "User enrollment")
{
  TC_AWAIT(enableOidc());
  auto serverUser = trustchain.makeUser();
  auto sDevice = serverUser.makeDevice();
  auto server = sDevice.createCore();

  auto const oidcConfig = TestConstants::oidcConfig();
  auto const martineIdToken = TC_AWAIT(getOidcToken(oidcConfig, "martine"));

  auto const provisionalIdentity = trustchain.makeEmailProvisionalUser();
  auto const verifEmail = boost::variant2::get<Email>(provisionalIdentity.value);
  auto const email = PreverifiedEmail{verifEmail.string()};
  auto const emailVerification = Verification::Verification{email};
  auto const verifPhoneNumber = makePhoneNumber();
  auto const phoneNumber = PreverifiedPhoneNumber{verifPhoneNumber.string()};
  auto const phoneNumberVerification = Verification::Verification{phoneNumber};
  auto const providerId = oidcProviderId(server->sdkInfo().trustchainId, oidcConfig.issuer, oidcConfig.clientId);
  auto const subject = getOidcSubject(martineIdToken);
  auto const oidcVerification = PreverifiedOidc{providerId, subject};

  auto const clearPassphrase = "Prenez1ChewingGumEmile!";
  auto const prehashedAndEncryptedPassphraseVerification = createPAEPVerification(clearPassphrase);
  auto enrolledUser = trustchain.makeUser();

  SECTION("server")
  {
    SECTION("enrolls a user with an email address")
    {
      REQUIRE_NOTHROW(TC_AWAIT(server->enrollUser(enrolledUser.identity, {emailVerification})));
    }

    SECTION("enrolls a user with a phone number")
    {
      REQUIRE_NOTHROW(TC_AWAIT(server->enrollUser(enrolledUser.identity, {phoneNumberVerification})));
    }

    SECTION("enrolls a user with oidc")
    {
      REQUIRE_NOTHROW(TC_AWAIT(server->enrollUser(enrolledUser.identity, {oidcVerification})));
    }

    SECTION("enrolls a user with every preverified verification method")
    {
      REQUIRE_NOTHROW(TC_AWAIT(
          server->enrollUser(enrolledUser.identity, {emailVerification, phoneNumberVerification, oidcVerification, prehashedAndEncryptedPassphraseVerification})));
    }

    SECTION("stays STOPPED after enrolling a user")
    {
      REQUIRE_NOTHROW(
          TC_AWAIT(server->enrollUser(enrolledUser.identity, {emailVerification, phoneNumberVerification})));
      CHECK(server->status() == Status::Stopped);
    }
  }

  SECTION("enrolled user")
  {
    auto const clearData = "new enrollment feature";
    auto device1 = enrolledUser.makeDevice();
    auto enrolledUserLaptop = device1.createCore();

    TC_AWAIT(server->enrollUser(enrolledUser.identity, {emailVerification, phoneNumberVerification, oidcVerification, prehashedAndEncryptedPassphraseVerification}));
    auto verificationCode = TC_AWAIT(getVerificationCode(verifEmail));

    auto const disposableIdentity = trustchain.makeUser();
    TC_AWAIT(server->start(disposableIdentity.identity));
    auto verificationKey = TC_AWAIT(server->generateVerificationKey());
    TC_AWAIT(server->registerIdentity(VerificationKey{verificationKey}));

    SECTION("must verify new devices")
    {
      auto device2 = enrolledUser.makeDevice();
      auto enrolledUserPhone = device2.createCore();
      auto device3 = enrolledUser.makeDevice();
      auto enrolledUserTablet = device3.createCore();
      auto device4 = enrolledUser.makeDevice();
      auto enrolledUserLaptop2 = device4.createCore();

      REQUIRE(TC_AWAIT(enrolledUserLaptop->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(
          TC_AWAIT(enrolledUserLaptop->verifyIdentity(Verification::ByEmail{verifEmail, verificationCode})));

      verificationCode = TC_AWAIT(getVerificationCode(verifPhoneNumber));
      REQUIRE(TC_AWAIT(enrolledUserPhone->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(
          TC_AWAIT(enrolledUserPhone->verifyIdentity(Verification::ByPhoneNumber{verifPhoneNumber, verificationCode})));

      REQUIRE(TC_AWAIT(enrolledUserTablet->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      auto testNonce = TC_AWAIT(enrolledUserTablet->createOidcNonce());
      enrolledUserTablet->setOidcTestNonce(testNonce);
      REQUIRE_NOTHROW(TC_AWAIT(enrolledUserTablet->verifyIdentity(martineIdToken)));

      REQUIRE(TC_AWAIT(enrolledUserLaptop2->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(TC_AWAIT(enrolledUserLaptop2->verifyIdentity(Passphrase{clearPassphrase})));
    }

    SECTION("can attach a provisional identity")
    {
      std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*server, clearData, {provisionalIdentity.publicIdentity}));

      REQUIRE(TC_AWAIT(enrolledUserLaptop->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(
          TC_AWAIT(enrolledUserLaptop->verifyIdentity(Verification::ByEmail{verifEmail, verificationCode})));

      REQUIRE(TC_AWAIT(enrolledUserLaptop->attachProvisionalIdentity(provisionalIdentity.secretIdentity)).status ==
              Status::Ready);

      REQUIRE_NOTHROW(checkDecrypt({enrolledUserLaptop}, clearData, encryptedData));
    }

    SECTION("access data shared before first verification")
    {
      std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*server, clearData, {enrolledUser.spublicIdentity()}));

      REQUIRE(TC_AWAIT(enrolledUserLaptop->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(
          TC_AWAIT(enrolledUserLaptop->verifyIdentity(Verification::ByEmail{verifEmail, verificationCode})));

      REQUIRE_NOTHROW(checkDecrypt({enrolledUserLaptop}, clearData, encryptedData));
    }

    SECTION("can be added to group before first verification")
    {
      auto const groupId = TC_AWAIT(server->createGroup({enrolledUser.spublicIdentity()}));
      std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*server, clearData, {}, {groupId}));

      REQUIRE(TC_AWAIT(enrolledUserLaptop->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(
          TC_AWAIT(enrolledUserLaptop->verifyIdentity(Verification::ByEmail{verifEmail, verificationCode})));

      REQUIRE_NOTHROW(checkDecrypt({enrolledUserLaptop}, clearData, encryptedData));
    }

    SECTION(
        "decrypts data shared with a provisional identity through a group "
        "before first verification")
    {
      auto const groupId = TC_AWAIT(server->createGroup({provisionalIdentity.publicIdentity}));
      std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*server, clearData, {}, {groupId}));

      REQUIRE(TC_AWAIT(enrolledUserLaptop->start(enrolledUser.identity)) == Status::IdentityVerificationNeeded);
      REQUIRE_NOTHROW(
          TC_AWAIT(enrolledUserLaptop->verifyIdentity(Verification::ByEmail{verifEmail, verificationCode})));

      REQUIRE(TC_AWAIT(enrolledUserLaptop->attachProvisionalIdentity(provisionalIdentity.secretIdentity)).status ==
              Status::Ready);

      REQUIRE_NOTHROW(checkDecrypt({enrolledUserLaptop}, clearData, encryptedData));
    }
  }
}
