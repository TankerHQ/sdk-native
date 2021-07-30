#include <Tanker/AsyncCore.hpp>

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Tanker/Functional/TrustchainFixture.hpp>

#include <mgs/base64.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Email.hpp>
#include <Helpers/Errors.hpp>

#include <doctest/doctest.h>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using Functional::TrustchainFixture;
using namespace Errors;

using namespace std::string_view_literals;

TEST_SUITE_BEGIN("provisionals");

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can encrypt and share with a provisional user")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(
      *aliceSession,
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}}));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(emailVerif));

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can claim the same provisional identity twice")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(
      *aliceSession,
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}}));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}));

  auto const result2 = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result2.status == Tanker::Status::Ready);

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob must verify his identity to claim a provisional identity")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->encrypt(
          make_buffer("my clear data is clear"),
          {SPublicIdentity{
              Identity::getPublicIdentity(bobProvisionalIdentity)}})),
      Errors::Errc::IdentityAlreadyAttached);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob can decrypt a provisional share claimed by a revoked device")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(
      *aliceSession,
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}}));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result.status == Status::IdentityVerificationNeeded);
  auto const aliceVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{aliceVerificationCode}}));

  TC_AWAIT(bobSession->revokeDevice(bobSession->deviceId().get()));

  auto bobDevice2 = bob.makeDevice();
  auto bobSession2 = TC_AWAIT(bobDevice2.open());
  REQUIRE_NOTHROW(checkDecrypt({bobSession2}, clearData, encryptedData));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can revoke a device, claim a provisional identity and "
                  "decrypt on multiple devices")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto const aliceEmail = Email{"alice1.test@tanker.io"};
  auto const aliceProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), aliceEmail);
  auto const aliceSession = TC_AWAIT(aliceDevice.open());

  auto aliceSecondDevice = alice.makeDevice();
  auto aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());
  REQUIRE_NOTHROW(TC_AWAIT(
      aliceSecondSession->revokeDevice(aliceSecondSession->deviceId().get())));

  auto aliceThirdDevice = alice.makeDevice();
  auto aliceThirdSession = TC_AWAIT(aliceThirdDevice.open());

  auto const clearData = "my clear data is clear";

  auto const encryptedData =
      TC_AWAIT(encrypt(*bobSession,
                       clearData,
                       {SPublicIdentity{Identity::getPublicIdentity(
                           aliceProvisionalIdentity)}}));

  REQUIRE_EQ(TC_AWAIT(aliceSession->attachProvisionalIdentity(
                          SSecretProvisionalIdentity{aliceProvisionalIdentity}))
                 .status,
             Status::IdentityVerificationNeeded);
  auto const aliceVerificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->verifyProvisionalIdentity(
      Unlock::EmailVerification{aliceEmail, aliceVerificationCode})));

  REQUIRE_NOTHROW(checkDecrypt(
      {aliceSession, aliceThirdSession}, clearData, encryptedData));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can claim when there is nothing to claim")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(emailVerif));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can attach a provisional identity without verification")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData = TC_AWAIT(encrypt(
      *aliceSession,
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}}));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto const bobSession = bobDevice.createCore();
  TC_AWAIT(bobSession->start(bob.identity));
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->registerIdentity(emailVerif));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result.status == Status::Ready);

  REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Handles incorrect verification codes when verifying "
                  "provisional identity")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(
          Unlock::EmailVerification{bobEmail, VerificationCode{"invalid"}})),
      Errc::InvalidVerification);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Charlie cannot attach an already attached provisional "
                  "identity")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}));

  result = TC_AWAIT(charlieSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(
          charlieSession->verifyProvisionalIdentity(Unlock::EmailVerification{
              bobEmail, VerificationCode{bobVerificationCode}})),
      Errc::IdentityAlreadyAttached);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob cannot verify a provisionalIdentity without attaching it first")
{
  auto const bobEmail = makeEmail();
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
          bobEmail, VerificationCode{"DUMMY_CODE_FOR_FASTER_TESTS"}})),
      Errc::PreconditionFailed);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob's has multiple provisional identities with the same email")
{
  auto const clearData = "my clear data is clear";

  auto const bobEmail = makeEmail();
  std::array const bobProvisionalIdentities = {
      Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id),
                                          bobEmail),
      Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id),
                                          bobEmail),
      Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id),
                                          bobEmail)};
  auto constexpr nb_ids = std::tuple_size_v<decltype(bobProvisionalIdentities)>;

  SUBCASE("Alice can share with Bob provisional identities")
  {
    for (auto const& id : bobProvisionalIdentities)
    {
      CAPTURE(id);
      std::vector<uint8_t> encryptedData =
          TC_AWAIT(encrypt(*aliceSession,
                           clearData,
                           {SPublicIdentity{Identity::getPublicIdentity(id)}}));

      auto result = TC_AWAIT(bobSession->attachProvisionalIdentity(
          SSecretProvisionalIdentity{id}));
      REQUIRE(result.status == Status::IdentityVerificationNeeded);
      auto bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
      TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
          bobEmail, VerificationCode{bobVerificationCode}}));

      REQUIRE_NOTHROW(checkDecrypt({bobSession}, clearData, encryptedData));
    }
  }
  SUBCASE(
      "Alice can share with Bob's not already attached provisional identities")
  {
    auto result = TC_AWAIT(bobSession->attachProvisionalIdentity(
        SSecretProvisionalIdentity{bobProvisionalIdentities[0]}));
    REQUIRE(result.status == Status::IdentityVerificationNeeded);
    auto bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
    TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
        bobEmail, VerificationCode{bobVerificationCode}}));

    TANKER_CHECK_THROWS_WITH_CODE(
        TC_AWAIT(encrypt(*aliceSession,
                         clearData,
                         {SPublicIdentity{Identity::getPublicIdentity(
                             bobProvisionalIdentities[0])}})),
        Errc::IdentityAlreadyAttached);

    for (auto i = 1u; i < nb_ids; ++i)
    {
      CAPTURE(bobProvisionalIdentities[i]);
      REQUIRE_NOTHROW(
          TC_AWAIT(encrypt(*aliceSession,
                           clearData,
                           {SPublicIdentity{Identity::getPublicIdentity(
                               bobProvisionalIdentities[i])}})));
    }
  }
}

TEST_SUITE_END();
