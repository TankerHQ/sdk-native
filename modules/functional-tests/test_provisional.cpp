#include <Tanker/AsyncCore.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Tanker/Functional/TrustchainFixture.hpp>
#include <Tanker/Types/PhoneNumber.hpp>

#include <mgs/base64.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Email.hpp>
#include <Helpers/Errors.hpp>

#include "TestSuite.hpp"

#include "CheckDecrypt.hpp"

using namespace Tanker;
using Functional::TrustchainFixture;
using namespace Errors;

using namespace std::string_view_literals;

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt and share with a provisional user")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {bobProvisional.publicIdentity}));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(bobProvisional.secretIdentity));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Verification::ByEmail{bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(emailVerif));

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt and share with a duplicate provisional user")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData =
      TC_AWAIT(encrypt(*aliceSession, clearData, {bobProvisional.publicIdentity, bobProvisional.publicIdentity}));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(bobProvisional.secretIdentity));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Verification::ByEmail{bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(emailVerif));

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Alice cannot encrypt and share with two provisional users who "
                 "have the same email address")
{
  auto const email = makeEmail();

  auto const secretProvisionalIdentity1 =
      SSecretProvisionalIdentity(Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), email));
  auto const publicProvisionalIdentity1 =
      SPublicIdentity(Identity::getPublicIdentity(secretProvisionalIdentity1.string()));
  Functional::AppProvisionalUser bobProvisional{email, secretProvisionalIdentity1, publicProvisionalIdentity1};

  auto const secretProvisionalIdentity2 =
      SSecretProvisionalIdentity(Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), email));
  auto const publicProvisionalIdentity2 =
      SPublicIdentity(Identity::getPublicIdentity(secretProvisionalIdentity2.string()));
  Functional::AppProvisionalUser charlieProvisional{email, secretProvisionalIdentity2, publicProvisionalIdentity2};

  auto const clearData = "my clear data is clear";
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(encrypt(*aliceSession, clearData, {bobProvisional.publicIdentity, charlieProvisional.publicIdentity})),
      Errc::InvalidArgument,
      "using multiple provisional identities for the same target");
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt and share with multiple provisional users")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);
  auto const charlieProvisional = trustchain.makeEmailProvisionalUser();
  auto const charlieEmail = boost::variant2::get<Email>(charlieProvisional.value);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData =
      TC_AWAIT(encrypt(*aliceSession, clearData, {bobProvisional.publicIdentity, charlieProvisional.publicIdentity}));

  TC_AWAIT(attachProvisionalIdentity(*bobSession, bobProvisional));
  TC_AWAIT(attachProvisionalIdentity(*charlieSession, charlieProvisional));

  REQUIRE_NOTHROW(checkDecrypt({bobSession, charlieSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt and then share with a provisional user")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData));

  TC_AWAIT(
      aliceSession->share({TC_AWAIT(AsyncCore::getResourceId(encryptedData))}, {bobProvisional.publicIdentity}, {}));

  TC_AWAIT(attachProvisionalIdentity(*bobSession, bobProvisional));

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt and then share with multiple provisional users")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);
  auto const charlieProvisional = trustchain.makeEmailProvisionalUser();
  auto const charlieEmail = boost::variant2::get<Email>(charlieProvisional.value);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData));

  TC_AWAIT(aliceSession->share({TC_AWAIT(AsyncCore::getResourceId(encryptedData))},
                               {bobProvisional.publicIdentity, charlieProvisional.publicIdentity},
                               {}));

  TC_AWAIT(attachProvisionalIdentity(*bobSession, bobProvisional));
  TC_AWAIT(attachProvisionalIdentity(*charlieSession, charlieProvisional));

  REQUIRE_NOTHROW(checkDecrypt({bobSession, charlieSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture, "Bob can claim the same provisional identity twice")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {bobProvisional.publicIdentity}));

  TC_AWAIT(attachProvisionalIdentity(*bobSession, bobProvisional));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(bobProvisional.secretIdentity));
  CHECK(result.status == Tanker::Status::Ready);

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can't share with a claimed provisional identity")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  TC_AWAIT(attachProvisionalIdentity(*bobSession, bobProvisional));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->encrypt(make_buffer("my clear data is clear"), {bobProvisional.publicIdentity})),
      Errors::Errc::IdentityAlreadyAttached);
}

TEST_CASE_METHOD(TrustchainFixture, "Bob can claim a provisional identity with a phone number verification")
{
  auto const bobProvisionalIdentity = trustchain.makePhoneNumberProvisionalUser();

  TC_AWAIT(attachProvisionalIdentity(*bobSession, bobProvisionalIdentity));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->encrypt(make_buffer("my clear data is clear"), {bobProvisionalIdentity.publicIdentity})),
      Errors::Errc::IdentityAlreadyAttached);
}

TEST_CASE_METHOD(TrustchainFixture, "Bob can claim when there is nothing to claim")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(bobProvisional.secretIdentity));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Verification::ByEmail{bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(emailVerif));
}

TEST_CASE_METHOD(TrustchainFixture, "Bob can attach an email provisional identity without verification")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {bobProvisional.publicIdentity}));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto const bobSession = bobDevice.createCore();
  TC_AWAIT(bobSession->start(bob.identity));
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Verification::ByEmail{bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->registerIdentity(emailVerif));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(bobProvisional.secretIdentity));
  CHECK(result.status == Status::Ready);

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture, "Bob can attach a phone number provisional identity without verification")
{
  auto const bobProvisional = trustchain.makePhoneNumberProvisionalUser();
  auto const bobPhone = boost::variant2::get<PhoneNumber>(bobProvisional.value);

  auto const clearData = "my clear data is clear";
  auto const encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {bobProvisional.publicIdentity}));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto const bobSession = bobDevice.createCore();
  TC_AWAIT(bobSession->start(bob.identity));
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobPhone));
  auto const verif = Verification::ByPhoneNumber{bobPhone, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->registerIdentity(verif));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(bobProvisional.secretIdentity));
  CHECK(result.status == Status::Ready);

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Handles incorrect verification codes when verifying "
                 "provisional identity")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(bobProvisional.secretIdentity));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(Verification::ByEmail{bobEmail, VerificationCode{"invalid"}})),
      Errc::InvalidVerification);
}

TEST_CASE_METHOD(TrustchainFixture,
                 "Charlie cannot attach an already attached provisional "
                 "identity")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();

  TC_AWAIT(attachProvisionalIdentity(*bobSession, bobProvisional));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(attachProvisionalIdentity(*charlieSession, bobProvisional)),
                                Errc::IdentityAlreadyAttached);
}

TEST_CASE_METHOD(TrustchainFixture, "Bob cannot verify a provisionalIdentity without attaching it first")
{
  auto const bobProvisional = trustchain.makeEmailProvisionalUser();
  auto const bobEmail = boost::variant2::get<Email>(bobProvisional.value);

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(bobSession->verifyProvisionalIdentity(
                                    Verification::ByEmail{bobEmail, VerificationCode{"DUMMY_CODE_FOR_FASTER_TESTS"}})),
                                Errc::PreconditionFailed);
}

TEST_CASE_METHOD(TrustchainFixture, "Bob's has multiple provisional identities with the same email")
{
  auto const clearData = "my clear data is clear";

  auto const bobEmail = makeEmail();
  std::array const bobProvisionalIdentities = {
      Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), bobEmail),
      Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), bobEmail),
      Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), bobEmail)};
  auto constexpr nb_ids = std::tuple_size_v<decltype(bobProvisionalIdentities)>;

  SECTION("Alice can share with Bob provisional identities")
  {
    for (auto const& id : bobProvisionalIdentities)
    {
      CAPTURE(id);
      std::vector<uint8_t> encryptedData =
          TC_AWAIT(encrypt(*aliceSession, clearData, {SPublicIdentity{Identity::getPublicIdentity(id)}}));

      auto result = TC_AWAIT(bobSession->attachProvisionalIdentity(SSecretProvisionalIdentity{id}));
      REQUIRE(result.status == Status::IdentityVerificationNeeded);
      auto bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
      TC_AWAIT(bobSession->verifyProvisionalIdentity(
          Verification::ByEmail{bobEmail, VerificationCode{bobVerificationCode}}));

      REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
    }
  }
  SECTION("Alice can share with Bob's not already attached provisional identities")
  {
    auto result =
        TC_AWAIT(bobSession->attachProvisionalIdentity(SSecretProvisionalIdentity{bobProvisionalIdentities[0]}));
    REQUIRE(result.status == Status::IdentityVerificationNeeded);
    auto bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
    TC_AWAIT(
        bobSession->verifyProvisionalIdentity(Verification::ByEmail{bobEmail, VerificationCode{bobVerificationCode}}));

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(encrypt(
            *aliceSession, clearData, {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentities[0])}})),
        Errc::IdentityAlreadyAttached);

    for (auto i = 1u; i < nb_ids; ++i)
    {
      CAPTURE(bobProvisionalIdentities[i]);
      REQUIRE_NOTHROW(TC_AWAIT(encrypt(
          *aliceSession, clearData, {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentities[i])}})));
    }
  }
}
