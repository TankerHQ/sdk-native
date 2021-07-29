#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest/doctest.h>

#include "CheckDecrypt.hpp"

using namespace Tanker;
using Tanker::Functional::TrustchainFixture;

TEST_SUITE_BEGIN("Groups");

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can create a group with Bob")
{
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->createGroup(
      {bob.spublicIdentity(), alice.spublicIdentity()})));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice uses encrypt to share with a group")
{
  auto myGroup = TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData =
      TC_AWAIT(encrypt(*aliceSession, clearData, {}, {myGroup}));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice encrypts and shares with a group")
{
  auto myGroup = TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData =
      TC_AWAIT(encrypt(*aliceSession, clearData));
  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->share({resourceId}, {}, {myGroup})));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "updateGroupMembers throws when given an invalid arguments")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

  // invalid identities
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->updateGroupMembers(
                                    groupId, {SPublicIdentity{""}}, {})),
                                Errors::Errc::InvalidArgument);

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->updateGroupMembers(
                                    groupId, {SPublicIdentity{"AAAA="}}, {})),
                                Errors::Errc::InvalidArgument);

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->updateGroupMembers(
          groupId,
          {SPublicIdentity{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBB"
                           "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}},
          {})),
      Errors::Errc::InvalidArgument);

  // invalid groupId
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->updateGroupMembers(
          SGroupId{""}, {alice.spublicIdentity()}, {})),
      Errors::Errc::InvalidArgument);
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->updateGroupMembers(
          SGroupId{"AAAA="}, {alice.spublicIdentity()}, {})),
      Errors::Errc::InvalidArgument);
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->updateGroupMembers(
          SGroupId{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBB"
                   "BBBBBBBBBBBBBBBBBBBBBBBBBBB="},
          {alice.spublicIdentity()},
          {})),
      Errors::Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Can add users to a group")
{
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
      aliceSession->updateGroupMembers(groupId, {bob.spublicIdentity()}, {})));
  REQUIRE_NOTHROW(TC_AWAIT(
      aliceSession->updateGroupMembers(groupId, {bob.spublicIdentity()}, {})));

  REQUIRE_NOTHROW(decryptedData =
                      TC_AWAIT(decrypt(*bobSession, encryptedData)));

  CHECK(decryptedData == clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Can transitively add users to a group")
{
  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;

  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));
  TC_AWAIT(
      bobSession->updateGroupMembers(groupId, {charlie.spublicIdentity()}, {}));
  TC_AWAIT(charlieSession->updateGroupMembers(
      groupId, {alice.spublicIdentity()}, {}));

  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*charlieSession, clearData, {}, {groupId})));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can't add Bob's already attached "
                  "provisional identity to a group")
{
  auto const bobEmail = Email{"bob13.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const verification = Unlock::Verification{Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->createGroup({SPublicIdentity{
          Identity::getPublicIdentity(bobProvisionalIdentity)}})),
      Errors::Errc::IdentityAlreadyAttached);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice shares with a group with Bob as a provisional user")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto const charlieEmail = Email{"charlie.test@tanker.io"};
  auto const charlieProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), charlieEmail);

  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)},
       SPublicIdentity{
           Identity::getPublicIdentity(charlieProvisionalIdentity)}}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*aliceSession, clearData, {}, {myGroup})));

  auto result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto verification = Unlock::Verification{Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

  std::string decrypted;
  REQUIRE_NOTHROW(decrypted = TC_AWAIT(decrypt(*bobSession, encryptedData)));
  CHECK(decrypted == clearData);

  result = TC_AWAIT(charlieSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{charlieProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const charlieVerificationCode =
      TC_AWAIT(getVerificationCode(charlieEmail));
  verification = Unlock::Verification{Unlock::EmailVerification{
      charlieEmail, VerificationCode{charlieVerificationCode}}};
  TC_AWAIT(charlieSession->verifyProvisionalIdentity(verification));

  REQUIRE_NOTHROW(decrypted =
                      TC_AWAIT(decrypt(*charlieSession, encryptedData)));
  CHECK(decrypted == clearData);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Alice shares with a group with Bob later added as a provisional user")
{
  auto const bobEmail = Email{"bob2.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto myGroup = TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*aliceSession, clearData, {}, {myGroup})));

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->updateGroupMembers(
      myGroup,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}},
      {})));

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

  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*aliceSession, clearData, {}, {myGroup})));

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
                  "Creates a group with mixed identities and a missing")
{
  // This user isn't registered on the trustchain!
  auto const charlie = trustchain.makeUser();

  /// This a provisional identity we tried to put in first place in the member
  /// list to check that the error reporting message is accurate.
  auto const brokenFmtId =
      R"json({{"target":"email","trustchain_id":"{:s}","value":"bob@tanker.io","public_encryption_key":"wpDs8fba4xcsDWmZvfxkPEY9E2St+P7LFNb0fSQT83I=","public_signature_key":"n6Iimfg/35a8AbIMMLHwzfSY83tYKdVGiQEN0XwCluw="}})json";
  auto const brokenId = SPublicIdentity{
      mgs::base64::encode(fmt::format(brokenFmtId, trustchain.id))};
  try
  {
    TC_AWAIT(aliceSession->createGroup({brokenId, charlie.spublicIdentity()}));
    CHECK(false);
  }
  catch (Tanker::Errors::Exception const& e)
  {
    auto const what = std::string_view(e.what());
    CHECK(what.find(charlie.spublicIdentity().string()) !=
          std::string_view::npos);
  }
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can't do a no-op update to a group")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(aliceSession->updateGroupMembers(groupId, {}, {})),
      Errors::Errc::InvalidArgument,
      "no members to add or remove");
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice shares with a group with Bob later added as a "
                  "provisional user when Bob has already verified the group")
{
  auto const bobEmail = Email{"bob4.tanker@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto myGroup = TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*aliceSession, clearData, {}, {myGroup})));

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->updateGroupMembers(
      myGroup,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}},
      {})));

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
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto myGroup = TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));
  TC_AWAIT(aliceSession->revokeDevice(TC_AWAIT(aliceSession->deviceId())));
  REQUIRE_NOTHROW(
      TC_AWAIT(bobSession->encrypt(make_buffer("paf"), {}, {myGroup})));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Can remove users from a group")
{
  auto const groupId = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), bob.spublicIdentity()}));
  TC_AWAIT(
      aliceSession->updateGroupMembers(groupId, {}, {bob.spublicIdentity()}));

  // Bob can't update the group
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(bobSession->updateGroupMembers(
                                    groupId, {}, {alice.spublicIdentity()})),
                                Errors::AppdErrc::NotAUserGroupMember);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Can remove users twice from a group")
{
  auto const groupId = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), bob.spublicIdentity()}));
  TC_AWAIT(aliceSession->updateGroupMembers(
      groupId, {}, {bob.spublicIdentity(), bob.spublicIdentity()}));

  // Bob can't update the group
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(bobSession->updateGroupMembers(
                                    groupId, {}, {alice.spublicIdentity()})),
                                Errors::AppdErrc::NotAUserGroupMember);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Cannot remove someone who is not a member")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

  // Bob can't update the group
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->updateGroupMembers(
                                    groupId, {}, {bob.spublicIdentity()})),
                                Errors::AppdErrc::MissingUserGroupMembers);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Removed group members cannot decrypt")
{
  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;

  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity(),
                                          bob.spublicIdentity(),
                                          charlie.spublicIdentity()}));
  TC_AWAIT(
      bobSession->updateGroupMembers(groupId, {}, {alice.spublicIdentity()}));

  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(bobSession->encrypt(
                      make_buffer(clearData), {}, {groupId})));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)),
                                Errors::Errc::InvalidArgument);

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({charlieSession}, clearData, encryptedData)));
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Alice cannot decrypt when she removes herself from the group")
{
  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;

  auto const groupId = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), bob.spublicIdentity()}));
  TC_AWAIT(
      aliceSession->updateGroupMembers(groupId, {}, {alice.spublicIdentity()}));

  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(bobSession->encrypt(
                      make_buffer(clearData), {}, {groupId})));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Can add and remove users from a group")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));
  TC_AWAIT(
      aliceSession->updateGroupMembers(groupId, {bob.spublicIdentity()}, {}));
  TC_AWAIT(
      aliceSession->updateGroupMembers(groupId, {}, {bob.spublicIdentity()}));

  // Bob can't update the group
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(bobSession->updateGroupMembers(
                                    groupId, {}, {alice.spublicIdentity()})),
                                Errors::AppdErrc::NotAUserGroupMember);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Cannot remove the last user from a group")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->updateGroupMembers(
                                    groupId, {}, {alice.spublicIdentity()})),
                                Errors::AppdErrc::EmptyUserGroup);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Cannot add and remove the same user from a group")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(aliceSession->updateGroupMembers(
          groupId, {bob.spublicIdentity()}, {bob.spublicIdentity()})),
      Errors::Errc::InvalidArgument,
      "cannot both add and remove");
}

TEST_CASE_FIXTURE(TrustchainFixture, "Can remove provisional group members")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);
  auto const bobPublicProvisional =
      SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)};

  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), bobPublicProvisional}));
  TC_AWAIT(
      aliceSession->updateGroupMembers(myGroup, {}, {bobPublicProvisional}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*aliceSession, clearData, {}, {myGroup})));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const verification = Unlock::Verification{Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(decrypt(*bobSession, encryptedData)),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Can remove provisional group members twice")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);
  auto const bobPublicProvisional =
      SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)};

  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), bobPublicProvisional}));
  TC_AWAIT(aliceSession->updateGroupMembers(
      myGroup, {}, {bobPublicProvisional, bobPublicProvisional}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*aliceSession, clearData, {}, {myGroup})));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const verification = Unlock::Verification{Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(decrypt(*bobSession, encryptedData)),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Cannot add and remove the same provisional user from a group")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);
  auto const bobPublicProvisional =
      SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)};

  auto myGroup = TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(aliceSession->updateGroupMembers(
          myGroup, {bobPublicProvisional}, {bobPublicProvisional})),
      Errors::Errc::InvalidArgument,
      "cannot both add and remove");
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Can't remove claimed provisional group members as a provisional identity")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);
  auto const bobPublicProvisional =
      SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)};

  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), bobPublicProvisional}));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const verification = Unlock::Verification{Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->updateGroupMembers(
                                    myGroup, {}, {bobPublicProvisional})),
                                Errors::Errc::IdentityAlreadyAttached);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Can remove claimed provisional group members as a permanent identity")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);
  auto const bobPublicProvisional =
      SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)};

  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), bobPublicProvisional}));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const verification = Unlock::Verification{Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

  TC_AWAIT(
      aliceSession->updateGroupMembers(myGroup, {}, {bob.spublicIdentity()}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(
                      encrypt(*aliceSession, clearData, {}, {myGroup})));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(decrypt(*bobSession, encryptedData)),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Claimed provisional identities can update group")
{
  auto const bobEmail = Email{"bob2.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(),
       SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}}));

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const verification = Unlock::Verification{Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(verification));

  REQUIRE_NOTHROW(TC_AWAIT(
      bobSession->updateGroupMembers(myGroup, {}, {alice.spublicIdentity()})));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData =
                      TC_AWAIT(encrypt(*bobSession, clearData, {}, {myGroup})));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(decrypt(*aliceSession, encryptedData)),
                                Errors::Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can decrypt previous group shares with a group update")
{
  auto myGroup = TC_AWAIT(aliceSession->createGroup(
      {alice.spublicIdentity(), charlie.spublicIdentity()}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData =
      TC_AWAIT(encrypt(*aliceSession, clearData));
  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();
  TC_AWAIT(aliceSession->share({resourceId}, {}, {myGroup}));

  TC_AWAIT(aliceSession->updateGroupMembers(
      myGroup, {bob.spublicIdentity()}, {charlie.spublicIdentity()}));

  REQUIRE_NOTHROW(
      TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Cannot edit a group bob is not part of")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({alice.spublicIdentity()}));

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(
          bobSession->updateGroupMembers(groupId, {bob.spublicIdentity()}, {})),
      Errors::Errc::InvalidArgument,
      "user is not part of group");
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Don't share with group creator if not in the group")
{
  auto const groupId =
      TC_AWAIT(aliceSession->createGroup({bob.spublicIdentity()}));

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData =
      TC_AWAIT(encrypt(*bobSession, clearData, {}, {groupId}));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(decrypt(*aliceSession, encryptedData)),
                                Errors::Errc::InvalidArgument);
}

TEST_SUITE_END();
