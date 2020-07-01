#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest/doctest.h>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using Tanker::Functional::TrustchainFixture;

TEST_SUITE("Groups")
{
  TEST_CASE_FIXTURE(TrustchainFixture, "Alice can create a group with Bob")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->createGroup(
        {bob.spublicIdentity(), alice.spublicIdentity()})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture,
                    "Alice uses encrypt to share with a group")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    auto myGroup = TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));

    auto const clearData = make_buffer("my clear data is clear");
    std::vector<uint8_t> encryptedData(
        AsyncCore::encryptedSize(clearData.size()));
    REQUIRE_NOTHROW(TC_AWAIT(
        aliceSession->encrypt(encryptedData.data(), clearData, {}, {myGroup})));

    REQUIRE(TC_AWAIT(
        checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Alice encrypts and shares with a group")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevices = TC_AWAIT(bob.makeDevices(1));

    auto myGroup = TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));

    auto const clearData = "my clear data is clear";
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData =
                        TC_AWAIT(encrypt(*aliceSession, clearData)));
    auto const resourceId = AsyncCore::getResourceId(encryptedData).get();
    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->share({resourceId}, {}, {myGroup})));

    REQUIRE(TC_AWAIT(checkDecrypt(
        bobDevices, {std::make_tuple(make_buffer(clearData), encryptedData)})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Can add users to a group")
  {
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser();
    auto bobDevice = bob.makeDevice();
    auto bobSession = TC_AWAIT(bobDevice.open());

    auto const groupId =
        TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

    auto const clearData = "my clear data is clear";
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                        encrypt(*aliceSession, clearData, {}, {groupId})));

    std::string decryptedData;
    TANKER_CHECK_THROWS_WITH_CODE(
        decryptedData = TC_AWAIT(decrypt(*bobSession, encryptedData)),
        Errors::Errc::InvalidArgument);

    REQUIRE_NOTHROW(TC_AWAIT(
        aliceSession->updateGroupMembers(groupId, {bob.spublicIdentity()})));
    REQUIRE_NOTHROW(TC_AWAIT(
        aliceSession->updateGroupMembers(groupId, {bob.spublicIdentity()})));

    REQUIRE_NOTHROW(decryptedData =
                        TC_AWAIT(decrypt(*bobSession, encryptedData)));

    CHECK(decryptedData == clearData);
  }

  TEST_CASE_FIXTURE(TrustchainFixture, "Can transitively add users to a group")
  {
    auto Alice = trustchain.makeUser();
    auto Bob = trustchain.makeUser();
    auto Charlie = trustchain.makeUser();

    auto AliceDevice = Alice.makeDevice();
    auto BobDevice = Bob.makeDevice();
    auto CharlieDevice = Charlie.makeDevice();

    auto const clearData = "my clear data is clear";
    std::vector<uint8_t> encryptedData;
    {
      auto AliceSession = TC_AWAIT(AliceDevice.open());
      auto BobSession = TC_AWAIT(BobDevice.open());
      auto CharlieSession = TC_AWAIT(CharlieDevice.open());

      auto const groupId =
          TC_AWAIT(AliceSession->createGroup({Bob.spublicIdentity()}));
      TC_AWAIT(
          BobSession->updateGroupMembers(groupId, {Charlie.spublicIdentity()}));
      TC_AWAIT(CharlieSession->updateGroupMembers(groupId,
                                                  {Alice.spublicIdentity()}));

      REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                          encrypt(*CharlieSession, clearData, {}, {groupId})));
    }

    REQUIRE(TC_AWAIT(checkDecrypt(
        {AliceDevice},
        {std::make_tuple(make_buffer(clearData), encryptedData)})));
  }

  TEST_CASE_FIXTURE(TrustchainFixture,
                    "Alice shares with a group with Bob as a provisional user")
  {
    auto const bobEmail = Email{"bob1.test@tanker.io"};
    auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
        mgs::base64::encode(trustchain.id), bobEmail);

    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto myGroup = TC_AWAIT(aliceSession->createGroup({SPublicIdentity{
        Identity::getPublicIdentity(bobProvisionalIdentity)}}));

    auto const clearData = "my clear data is clear";
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                        encrypt(*aliceSession, clearData, {}, {myGroup})));

    auto bob = trustchain.makeUser();
    auto bobDevice = bob.makeDevice();
    auto bobSession = TC_AWAIT(bobDevice.open());

    auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
        SSecretProvisionalIdentity{bobProvisionalIdentity}));
    REQUIRE(result.status == Status::IdentityVerificationNeeded);
    auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
    auto const verification = Unlock::Verification{Unlock::EmailVerification{
        bobEmail, VerificationCode{bobVerificationCode}}};
    TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

    std::string decrypted;
    REQUIRE_NOTHROW(decrypted = TC_AWAIT(decrypt(*bobSession, encryptedData)));
    CHECK(decrypted == clearData);
  }

  TEST_CASE_FIXTURE(
      TrustchainFixture,
      "Alice shares with a group with Bob later added as a provisional user")
  {
    auto const bobEmail = Email{"bob2.test@tanker.io"};
    auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
        mgs::base64::encode(trustchain.id), bobEmail);

    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto myGroup =
        TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

    auto const clearData = "my clear data is clear";
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                        encrypt(*aliceSession, clearData, {}, {myGroup})));

    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->updateGroupMembers(
        myGroup,
        {SPublicIdentity{
            Identity::getPublicIdentity(bobProvisionalIdentity)}})));

    auto bob = trustchain.makeUser();
    auto bobDevice = bob.makeDevice();
    auto bobSession = TC_AWAIT(bobDevice.open());

    auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
    auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
        SSecretProvisionalIdentity{bobProvisionalIdentity}));
    REQUIRE(result.status == Status::IdentityVerificationNeeded);
    auto const verification = Unlock::Verification{Unlock::EmailVerification{
        bobEmail, VerificationCode{bobVerificationCode}}};
    TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

    std::string decrypted;
    REQUIRE_NOTHROW(decrypted = TC_AWAIT(decrypt(*bobSession, encryptedData)));
    CHECK(decrypted == clearData);
  }

  TEST_CASE_FIXTURE(TrustchainFixture,
                    "Alice shares with a group with Bob as a provisional user "
                    "when Bob has already verified the group")
  {
    auto const bobEmail = Email{"bob3.test@tanker.io"};
    auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
        mgs::base64::encode(trustchain.id), bobEmail);

    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto myGroup = TC_AWAIT(aliceSession->createGroup({SPublicIdentity{
        Identity::getPublicIdentity(bobProvisionalIdentity)}}));

    auto const clearData = "my clear data is clear";
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                        encrypt(*aliceSession, clearData, {}, {myGroup})));

    auto bob = trustchain.makeUser();
    auto bobDevice = bob.makeDevice();
    auto bobSession = TC_AWAIT(bobDevice.open());

    // verify the group
    TC_AWAIT(encrypt(*bobSession, "", {}, {myGroup}));

    auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
    auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
        SSecretProvisionalIdentity{bobProvisionalIdentity}));
    REQUIRE(result.status == Status::IdentityVerificationNeeded);
    TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
        bobEmail, VerificationCode{bobVerificationCode}}));

    std::string decrypted;
    REQUIRE_NOTHROW(decrypted = TC_AWAIT(decrypt(*bobSession, encryptedData)));
    CHECK(decrypted == clearData);
  }

  TEST_CASE_FIXTURE(TrustchainFixture,
                    "Alice shares with a group with Bob later added as a "
                    "provisional user when Bob has already verified the group")
  {
    auto const bobEmail = Email{"bob4.tanker@tanker.io"};
    auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
        mgs::base64::encode(trustchain.id), bobEmail);

    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto myGroup =
        TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

    auto const clearData = "my clear data is clear";
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                        encrypt(*aliceSession, clearData, {}, {myGroup})));

    REQUIRE_NOTHROW(TC_AWAIT(aliceSession->updateGroupMembers(
        myGroup,
        {SPublicIdentity{
            Identity::getPublicIdentity(bobProvisionalIdentity)}})));

    auto bob = trustchain.makeUser();
    auto bobDevice = bob.makeDevice();
    auto bobSession = TC_AWAIT(bobDevice.open());

    // verify the group
    std::vector<uint8_t> useless(AsyncCore::encryptedSize(0));
    TC_AWAIT(bobSession->encrypt(useless.data(), {}, {}, {myGroup}));

    auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
        SSecretProvisionalIdentity{bobProvisionalIdentity}));
    REQUIRE(result.status == Status::IdentityVerificationNeeded);
    auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
    TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
        bobEmail, VerificationCode{bobVerificationCode}}));

    std::string decrypted;
    REQUIRE_NOTHROW(decrypted = TC_AWAIT(decrypt(*bobSession, encryptedData)));
    CHECK(decrypted == clearData);
  }

  TEST_CASE_FIXTURE(TrustchainFixture,
                    "It should share with a group after the device that "
                    "created the group has been revoked")
  {
    auto alice = trustchain.makeUser(Functional::UserType::New);
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());

    auto bob = trustchain.makeUser(Functional::UserType::New);
    auto bobDevice = bob.makeDevice();
    auto bobSession = TC_AWAIT(bobDevice.open());

    auto myGroup =
        TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));
    TC_AWAIT(aliceSession->revokeDevice(TC_AWAIT(aliceSession->deviceId())));
    REQUIRE_NOTHROW(
        TC_AWAIT(bobSession->encrypt(make_buffer("paf"), {}, {myGroup})));
  }
}
