#include <string>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/HttpClient.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <Tanker/Functional/TrustchainFixture.hpp>

#include <doctest/doctest.h>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/WaitFor.hpp>

#include "CheckDecrypt.hpp"

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

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it throws when starting a session when the identity appId "
                  "is different from the one in tanker options")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto invalidIdentity =
      Identity::extract<Identity::SecretPermanentIdentity>(alice.identity);
  invalidIdentity.trustchainId[0]++;
  alice.identity = to_string(invalidIdentity);
  auto const core = TC_AWAIT(device.open());
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->start(alice.identity)),
                                Errors::Errc::InvalidArgument);
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
  CHECK_NOTHROW(TC_AWAIT(core->stop()));
  REQUIRE(core->status() == Status::Stopped);
  CHECK_NOTHROW(TC_AWAIT(waitFor(closeProm1)));

  // check that stopping a stopped session is a no-op
  CHECK_NOTHROW(TC_AWAIT(core->stop()));
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "it throws nice exceptions when giving the wrong identity type")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = device.createCore(Functional::SessionType::New);
  try
  {
    TC_AWAIT(core->start(alice.spublicIdentity().string()));
    CHECK_MESSAGE(false, "start() should have thrown");
  }
  catch (Errors::Exception const& e)
  {
    CAPTURE(e.what());
    CHECK(std::string(e.what()).find("got a public identity") !=
          std::string::npos);
  }
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), Email{"bob"});
  try
  {
    TC_AWAIT(core->start(bobProvisionalIdentity));
    CHECK_MESSAGE(false, "start() should have thrown");
  }
  catch (Errors::Exception const& e)
  {
    CAPTURE(e.what());
    CHECK(std::string(e.what()).find("got a provisional identity") !=
          std::string::npos);
  }
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it throws nice exceptions when giving an incorrect identity")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  TC_AWAIT(device.open(Functional::SessionType::New));

  auto core = device.createCore(Functional::SessionType::New);
  auto identity =
      Identity::extract<Identity::SecretPermanentIdentity>(alice.identity);
  ++identity.userSecret[0];
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->start(to_string(identity))),
                                DataStore::Errc::DatabaseCorrupt);
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
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->start(alice.identity)),
                                DataStore::Errc::DatabaseLocked);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "it throws the correct error when the server is down")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice(Functional::DeviceType::New);
  // connect to a (probably) closed port
  auto core = std::unique_ptr<AsyncCore, Functional::AsyncCoreDeleter>(
      new AsyncCore("https://127.0.0.1:65012",
                    device.getSdkInfo(),
                    device.writablePath()));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->start(device.identity())),
                                Errc::NetworkError);
}

TEST_CASE_FIXTURE(TrustchainFixture, "it can open a session on a second device")
{
  auto alice = trustchain.makeUser();

  auto device1 = alice.makeDevice();
  auto session = TC_AWAIT(device1.open());
  auto device2 = alice.makeDevice(Functional::DeviceType::New);
  REQUIRE_NOTHROW(TC_AWAIT(device2.open()));
}

namespace
{

void deauthSession(Tanker::AsyncCore& core)
{
  // set some random access token
  core.setHttpSessionToken("UUSFMmx4RfGONVaFl2IAVv1yN20ORd3SjLhcHfgJPys");
}
}

TEST_CASE_FIXTURE(TrustchainFixture, "a session of a new user can reauth")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();

  auto aliceSession = TC_AWAIT(aliceDevice.open());

  deauthSession(*aliceSession);

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData =
                      TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "a session of a new device can reauth")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  {
    auto aliceDevice = alice.makeDevice(Functional::DeviceType::New);
    auto aliceSession = TC_AWAIT(aliceDevice.open());
  }
  auto aliceDevice = alice.makeDevice(Functional::DeviceType::New);
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  deauthSession(*aliceSession);

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData =
                      TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "a session of an existing device can reauth")
{
  auto alice = trustchain.makeUser(Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  {
    auto aliceSession =
        TC_AWAIT(aliceDevice.open(Functional::SessionType::New));
  }
  auto aliceSession = TC_AWAIT(aliceDevice.open(Functional::SessionType::New));

  deauthSession(*aliceSession);

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData =
                      TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture, "It can encrypt/decrypt")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData =
                      TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE_EQ(decryptedData, clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "It can share explicitly with an equivalent self identity")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto alicepub = mgs::base64::decode(alice.spublicIdentity().string());
  alicepub.push_back(' ');
  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(
      encryptedData = TC_AWAIT(aliceSession->encrypt(
          clearData, {SPublicIdentity{mgs::base64::encode(alicepub)}})));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData =
                      TC_AWAIT(aliceSession->decrypt(encryptedData)));

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
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(
                      clearData, {bob.spublicIdentity()})));

  REQUIRE(TC_AWAIT(
      checkDecrypt(bobDevices, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can share a key he hasn't received yet")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto charlie = trustchain.makeUser();
  auto charlieDevices = TC_AWAIT(charlie.makeDevices(1));

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(
                      clearData, {bob.spublicIdentity()})));

  TC_AWAIT(
      bobSession->share({TC_AWAIT(AsyncCore::getResourceId(encryptedData))},
                        {charlie.spublicIdentity()},
                        {}));

  REQUIRE(TC_AWAIT(checkDecrypt(charlieDevices,
                                {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can encrypt without sharing with self")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());
  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(
      encryptedData = TC_AWAIT(aliceSession->encrypt(
          clearData, {bob.spublicIdentity()}, {}, Core::ShareWithSelf::No)));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)),
                                Errc::InvalidArgument);
  REQUIRE_NOTHROW(TC_AWAIT(bobSession->decrypt(encryptedData)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice cannot encrypt without sharing with anybody")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(
          aliceSession->encrypt(clearData, {}, {}, Core::ShareWithSelf::No)),
      Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can stream-encrypt without sharing with self")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());
  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  auto encryptor = TC_AWAIT(aliceSession->makeEncryptionStream(
      Streams::bufferViewToInputSource(clearData),
      {bob.spublicIdentity()},
      {},
      Core::ShareWithSelf::No));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptor));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)),
                                Errc::InvalidArgument);
  REQUIRE_NOTHROW(TC_AWAIT(bobSession->decrypt(encryptedData)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice cannot stream-encrypt without sharing with anybody")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->makeEncryptionStream(
                                    Streams::bufferViewToInputSource(clearData),
                                    {},
                                    {},
                                    Core::ShareWithSelf::No)),
                                Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Alice shares with all her devices")
{
  auto alice = trustchain.makeUser();
  auto aliceDevices = TC_AWAIT(alice.makeDevices(3));
  auto const aliceSession = TC_AWAIT(aliceDevices[0].open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
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
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData =
                      TC_AWAIT(aliceFirstSession->encrypt(clearData)));

  auto aliceSecondDevice = alice.makeDevice();
  auto const aliceSecondSession = TC_AWAIT(aliceSecondDevice.open());

  TC_AWAIT(aliceSecondSession->stop());

  REQUIRE_UNARY(TC_AWAIT(checkDecrypt(
      {aliceSecondDevice}, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(TrustchainFixture, "Bob will fail to decrypt without the key")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));

  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();

  std::vector<uint8_t> decryptedData;
  TANKER_CHECK_THROWS_WITH_CODE(
      decryptedData = TC_AWAIT(bobSession->decrypt(encryptedData)),
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
    std::vector<uint8_t> encryptedData;
    encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));
    resourceIds.emplace_back(AsyncCore::getResourceId(encryptedData).get());
    metaResources.emplace_back(std::move(clearData), std::move(encryptedData));
  }

  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->share(resourceIds, {bob.spublicIdentity()}, {})));
  REQUIRE(TC_AWAIT(checkDecrypt(bobDevice, metaResources)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can share multiple times the same resource to Bob")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto bob = trustchain.makeUser();
  auto bobDevice = TC_AWAIT(bob.makeDevices(1));

  auto const clearData = make_buffer("my clear data is clear");
  auto const encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));
  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();

  std::vector<SResourceId> resourceIds{resourceId, resourceId};

  REQUIRE_NOTHROW(
      TC_AWAIT(aliceSession->share(resourceIds, {bob.spublicIdentity()}, {})));
  REQUIRE_UNARY(TC_AWAIT(
      checkDecrypt({bobDevice}, {std::make_tuple(clearData, encryptedData)})));
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Alice cannot encrypt and share with more than 100 recipients")
{
  std::vector<SPublicIdentity> identities;
  for (int i = 0; i < 101; ++i)
  {
    auto const bobEmail = Email{fmt::format("bob{}.test@tanker.io", i)};
    auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
        mgs::base64::encode(trustchain.id), bobEmail);
    identities.push_back(
        SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)});
  }

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->encrypt(clearData, identities)),
      Errc::InvalidArgument);

  auto const encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));
  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->share({resourceId}, identities, {})),
      Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Alice can encrypt and share with a provisional user")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(
                      clearData,
                      {SPublicIdentity{Identity::getPublicIdentity(
                          bobProvisionalIdentity)}})));

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

  std::vector<uint8_t> decrypted;
  decrypted = TC_AWAIT(bobSession->decrypt(encryptedData));
  CHECK(decrypted == clearData);
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can claim the same provisional identity twice")
{
  auto const bobEmail = Email{"bob5.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(
                      clearData,
                      {SPublicIdentity{Identity::getPublicIdentity(
                          bobProvisionalIdentity)}})));

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

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob can decrypt a provisional share claimed by a revoked device")
{
  auto const bobEmail = Email{"alice5.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const encrypted = TC_AWAIT(aliceSession->encrypt(
      make_buffer("my clear data is clear"),
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}}));

  auto bob = trustchain.makeUser(Tanker::Functional::UserType::New);
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
  REQUIRE_NOTHROW(TC_AWAIT(bobSession2->decrypt(encrypted)));
}

TEST_CASE_FIXTURE(TrustchainFixture,
                  "Bob can claim when there is nothing to claim")
{
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

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
  auto const bobEmail = Email{"bob1.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(
                      clearData,
                      {SPublicIdentity{Identity::getPublicIdentity(
                          bobProvisionalIdentity)}})));

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
  auto const bobEmail = Email{"bob2.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

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
    "Charlie cannot attach an already attached provisional identity")
{
  auto const bobEmail = Email{"bob2.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  auto const clearData = make_buffer("my clear data is clear");
  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->encrypt(
      clearData,
      {SPublicIdentity{Identity::getPublicIdentity(bobProvisionalIdentity)}})));

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  auto result = TC_AWAIT(bobSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  auto bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
      bobEmail, VerificationCode{bobVerificationCode}}));

  auto charlie = trustchain.makeUser();
  auto charlieDevice = charlie.makeDevice();
  auto charlieSession = TC_AWAIT(charlieDevice.open());

  result = TC_AWAIT(charlieSession->attachProvisionalIdentity(
      SSecretProvisionalIdentity{bobProvisionalIdentity}));
  REQUIRE(result.status == Status::IdentityVerificationNeeded);
  bobVerificationCode = TC_AWAIT(getVerificationCode(bobEmail));
  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(
          charlieSession->verifyProvisionalIdentity(Unlock::EmailVerification{
              bobEmail, VerificationCode{bobVerificationCode}})),
      Errc::InvalidArgument);
}

TEST_CASE_FIXTURE(
    TrustchainFixture,
    "Bob cannot verify a provisionalIdentity without attaching it first")
{
  auto const bobEmail = Email{"bob3.test@tanker.io"};
  auto const bobProvisionalIdentity = Identity::createProvisionalIdentity(
      mgs::base64::encode(trustchain.id), bobEmail);

  auto bob = trustchain.makeUser();
  auto bobDevice = bob.makeDevice();
  auto bobSession = TC_AWAIT(bobDevice.open());

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(bobSession->verifyProvisionalIdentity(Unlock::EmailVerification{
          bobEmail, VerificationCode{"DUMMY_CODE_FOR_FASTER_TESTS"}})),
      Errc::PreconditionFailed);
}
