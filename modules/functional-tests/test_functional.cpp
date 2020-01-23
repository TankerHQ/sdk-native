#include <string>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <Tanker/Functional/TrustchainFixture.hpp>

#include <doctest.h>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/UniquePath.hpp>
#include <Helpers/WaitFor.hpp>

#include "CheckDecrypt.hpp"

#include <tconcurrent/async_wait.hpp>

#include <boost/scope_exit.hpp>

using namespace std::string_literals;

using namespace Tanker;
using namespace Tanker::Errors;
using namespace type_literals;
using Tanker::Functional::TrustchainFixture;

namespace Tanker
{
static std::ostream& operator<<(std::ostream& os, Status s)
{
  os << to_string(s);
  return os;
}
}

namespace
{
auto make_clear_data(std::initializer_list<std::string> clearText)
{
  std::vector<std::vector<uint8_t>> clearDatas;
  std::transform(begin(clearText),
                 end(clearText),
                 std::back_inserter(clearDatas),
                 [](auto&& clear) { return make_buffer(clear); });
  return clearDatas;
}
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open/close a session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto const core = TC_AWAIT(device.open());

  tc::promise<void> closeProm1;
  core->connectSessionClosed(
      [closeProm1]() mutable { closeProm1.set_value({}); });

  BOOST_SCOPE_EXIT_ALL(&)
  {
    core->disconnectSessionClosed();
  };

  REQUIRE(core->status() == Status::Ready);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  CHECK_NOTHROW(TC_AWAIT(waitFor(closeProm1)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open/close a session twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  BOOST_SCOPE_EXIT_ALL(&)
  {
    core->disconnectSessionClosed();
  };

  tc::promise<void> closeProm1;
  core->connectSessionClosed(
      [closeProm1]() mutable { closeProm1.set_value({}); });

  REQUIRE(core->status() == Status::Ready);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  CHECK_NOTHROW(TC_AWAIT(waitFor(closeProm1)));

  tc::promise<void> closeProm2;
  core->connectSessionClosed(
      [closeProm2]() mutable { closeProm2.set_value({}); });

  core = TC_AWAIT(device.open());
  REQUIRE(core->status() == Status::Ready);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);

  CHECK_NOTHROW(TC_AWAIT(waitFor(closeProm2)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can reopen a closed session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  CHECK_EQ(TC_AWAIT(core->start(alice.identity)), Status::Ready);
  CHECK_EQ(core->status(), Status::Ready);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it should prevent opening the same device twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());

  auto const core2 = device.createCore(Functional::SessionType::New);
  REQUIRE_THROWS(TC_AWAIT(core2->start(alice.identity)));
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open a session on a second device")
{
  auto alice = trustchain.makeUser();

  auto device1 = alice.makeDevice();
  auto session = TC_AWAIT(device1.open());
  auto device2 = alice.makeDevice(Functional::DeviceType::New);
  REQUIRE_NOTHROW(TC_AWAIT(device2.open()));
}

TEST_CASE_FIXTURE(TrustchainFixture, "It can encrypt/decrypt")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData)));
  std::vector<uint8_t> decryptedData(
      AsyncCore::decryptedSize(encryptedData).get());
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->decrypt(decryptedData.data(), encryptedData)));

  REQUIRE_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can stream encrypt/decrypt")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  std::vector<uint8_t> clearData(1024 * 1024 * 5);
  Crypto::randomFill(clearData);
  auto encryptor = TC_AWAIT(aliceSession->makeEncryptionStream(
      Streams::bufferViewToInputSource(clearData)));
  auto decryptor = TC_AWAIT(aliceSession->makeDecryptionStream(encryptor));

  auto decryptedData = TC_AWAIT(Streams::readAllStream(decryptor));
  CHECK_EQ(encryptor.resourceId(), decryptor.resourceId());
  CHECK_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can stream-encrypt and decrypt")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  std::vector<uint8_t> clearData(1024 * 1024 * 5);
  Crypto::randomFill(clearData);
  auto encryptor = TC_AWAIT(aliceSession->makeEncryptionStream(
      Streams::bufferViewToInputSource(clearData)));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptor));
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK_EQ(Core::getResourceId(encryptedData), encryptor.resourceId());
  CHECK_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can encrypt and stream-decrypt")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  auto const encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));
  auto decryptor = TC_AWAIT(aliceSession->makeDecryptionStream(
      Streams::bufferViewToInputSource(encryptedData)));

  auto decryptedData = TC_AWAIT(Streams::readAllStream(decryptor));
  CHECK_EQ(Core::getResourceId(encryptedData), decryptor.resourceId());
  CHECK_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice encrypt and share with Bob")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevices = TC_AWAIT(bob.makeDevices(2));

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->encrypt(
      encryptedData.data(), clearData, {bob.spublicIdentity()})));

  REQUIRE(TC_AWAIT(
      checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice shares with all her devices")
{
  auto alice = trustchain.makeUser();
  auto aliceDevices = TC_AWAIT(alice.makeDevices(3));
  auto const aliceSession = TC_AWAIT(aliceDevices[0].open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData)));
  TC_AWAIT(aliceSession->stop());
  REQUIRE(TC_AWAIT(
      checkDecrypt(aliceDevices, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice's second device can decrypt old resources")
{
  auto alice = trustchain.makeUser();
  auto aliceFirstDevice = alice.makeDevice();
  auto const aliceFirstSession = TC_AWAIT(aliceFirstDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(
      TC_AWAIT(aliceFirstSession->encrypt(encryptedData.data(), clearData)));

  auto aliceSecondDevice = alice.makeDevice();
  auto const aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());

  TC_AWAIT(aliceSecondSession->stop());

  REQUIRE_UNARY(TC_AWAIT(checkDecrypt(
      {aliceSecondDevice}, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob will timeout when trying to decrypt without the key")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData));

  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();

  std::vector<uint8_t> decryptedData;
  decryptedData.resize(clearData.size());

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(bobSession->decrypt(decryptedData.data(), encryptedData)),
      Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice can share many resources with Bob")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = TC_AWAIT(bob.makeDevices(1));

  auto const clearDatas = make_clear_data(
      {"to be clear, ", "or not be clear, ", "that is the test case..."});

  std::vector<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>>
      metaResources;
  metaResources.reserve(clearDatas.size());
  std::vector<SResourceId> resourceIds;
  resourceIds.reserve(clearDatas.size());
  for (auto const& clearData : clearDatas)
  {
    std::vector<uint8_t> encryptedData(
        AsyncCore::encryptedSize(clearData.size()));
    TC_AWAIT(aliceSession->encrypt(encryptedData.data(), clearData));
    resourceIds.emplace_back(AsyncCore::getResourceId(encryptedData).get());
    metaResources.emplace_back(std::move(clearData), std::move(encryptedData));
  }

  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->share(resourceIds, {bob.spublicIdentity()}, {})));
  REQUIRE(TC_AWAIT(checkDecrypt(bobDevice, metaResources)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can encrypt and share with a provisional user")
{
  auto const bobEmail = Email{"bob1@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->encrypt(
      encryptedData.data(),
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}})));

  auto bob = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto bobDevice = bob.makeDevice();
  auto const bobSession = TC_AWAIT(bobDevice.open());

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);

  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->verifyProvisionalIdentity(emailVerif));

  std::vector<uint8_t> decrypted(
      bobSession->decryptedSize(encryptedData).get());
  TC_AWAIT(bobSession->decrypt(decrypted.data(), encryptedData));
  CHECK(decrypted == clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can claim the same provisional identity twice")
{
  auto const bobEmail = Email{"bob5@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->encrypt(
      encryptedData.data(),
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}})));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}));

  auto const result2 = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result2.status == Tanker::Status::Ready);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can claim when there is nothing to claim")
{
  auto const bobEmail = Email{"bob1@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto bob = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto bobDevice = bob.makeDevice();
  auto const bobSession = TC_AWAIT(bobDevice.open());

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
  auto const bobEmail = Email{"bob1@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->encrypt(
      encryptedData.data(),
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}})));

  auto bob = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto bobDevice = bob.makeDevice();
  auto const bobSession =
      bobDevice.createCore(Tanker::Functional::SessionType::New);
  TC_AWAIT(bobSession->start(bob.identity));
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  auto const emailVerif = Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}};
  TC_AWAIT(bobSession->registerIdentity(emailVerif));

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  CHECK(result.status == Status::Ready);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Handles incorrect verification codes when verifying "
                  "provisional identity")
{
  auto const bobEmail = Email{"bob2@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto bob = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto const bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(
          Unlock::EmailVerification{bobEmail, VerificationCode{"invalid"}})),
      Errc::InvalidVerification);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob cannot verify a provisionalIdentity without attaching it first")
{
  auto const bobEmail = Email{"bob3@mail.com"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      cppcodec::base64_rfc4648::encode(trustchain.id), bobEmail);

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
          bobEmail, VerificationCode{"DUMMY_CODE_FOR_FASTER_TESTS"}})),
      Errc::PreconditionFailed);
}
