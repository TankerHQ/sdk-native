#include <Tanker/AsyncCore.hpp>
#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Encryptor/v10.hpp>
#include <Tanker/Encryptor/v11.hpp>
#include <Tanker/Encryptor/v4.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Encryptor/v8.hpp>
#include <Tanker/Encryptor/v9.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/IdentityUtils.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Types/SUserId.hpp>

#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Config.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/PhoneNumber.hpp>
#include <Helpers/WaitFor.hpp>

#include "CheckDecrypt.hpp"
#include "HttpHelpers.hpp"
#include "TestSuite.hpp"

#include <string>

using namespace std::string_literals;

using namespace Tanker;
using namespace Tanker::Errors;
using namespace type_literals;
using Tanker::Functional::TrustchainFixture;

namespace
{
constexpr auto fiveMiB = 5 * 1024 * 1024;
constexpr auto almostFiveMiB = fiveMiB - 30;
}

TEST_CASE_METHOD(TrustchainFixture,
                 "it throws when starting a session when the identity appId "
                 "is different from the one in tanker options")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto invalidIdentity = Identity::extract<Identity::SecretPermanentIdentity>(alice.identity);
  invalidIdentity.trustchainId[0]++;
  alice.identity = to_string(invalidIdentity);
  auto const core = TC_AWAIT(device.open());
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->start(alice.identity)), Errors::Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "it can open/close a session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto const core = TC_AWAIT(device.open());

  tc::promise<void> closeProm1;
  core->connectSessionClosed([closeProm1]() mutable { closeProm1.set_value({}); });

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

TEST_CASE_METHOD(TrustchainFixture, "it throws nice exceptions when giving the wrong identity type")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = device.createCore();

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(core->start(alice.spublicIdentity().string())), Errors::Errc::InvalidArgument, "got a public identity");

  auto const bobProvisionalIdentity =
      Identity::createProvisionalIdentity(mgs::base64::encode(trustchain.id), Email{"bob"});

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(core->start(bobProvisionalIdentity)), Errors::Errc::InvalidArgument, "got a provisional identity");
}

TEST_CASE_METHOD(TrustchainFixture, "it throws nice exceptions when giving an incorrect identity")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  // open and close a session
  TC_AWAIT(device.open());

  auto core = device.createCore();
  auto identity = Identity::extract<Identity::SecretPermanentIdentity>(alice.identity);
  ++identity.userSecret[0];
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->start(to_string(identity))), DataStore::Errc::DatabaseCorrupt);
}

TEST_CASE_METHOD(TrustchainFixture, "it can open/close a session twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  BOOST_SCOPE_EXIT_ALL(&)
  {
    core->disconnectSessionClosed();
  };

  tc::promise<void> closeProm1;
  core->connectSessionClosed([closeProm1]() mutable { closeProm1.set_value({}); });

  REQUIRE(core->status() == Status::Ready);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  CHECK_NOTHROW(TC_AWAIT(waitFor(closeProm1)));

  core = TC_AWAIT(device.open());

  tc::promise<void> closeProm2;
  core->connectSessionClosed([closeProm2]() mutable { closeProm2.set_value({}); });

  REQUIRE(core->status() == Status::Ready);
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);

  CHECK_NOTHROW(TC_AWAIT(waitFor(closeProm2)));
}

TEST_CASE_METHOD(TrustchainFixture, "it can reopen a closed session")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());
  TC_AWAIT(core->stop());
  REQUIRE(core->status() == Status::Stopped);
  CHECK(TC_AWAIT(core->start(alice.identity)) == Status::Ready);
  CHECK(core->status() == Status::Ready);
}

TEST_CASE_METHOD(TrustchainFixture, "it should prevent opening the same device twice")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();

  auto const core = TC_AWAIT(device.open());

  auto const core2 = device.createCore();
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core2->start(alice.identity)), Tanker::Errors::Errc::PreconditionFailed);
}

TEST_CASE_METHOD(TrustchainFixture, "it throws the correct error when the server is down")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  // connect to a (probably) closed port
  auto core = std::unique_ptr<AsyncCore, Functional::AsyncCoreDeleter>(
      new AsyncCore("https://127.0.0.1:65012", device.getSdkInfo(), device.writablePath(), device.writablePath()));

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->start(device.identity())), Errc::NetworkError);
}

namespace
{
void deauthSession(Tanker::AsyncCore& core)
{
  // set some random access token
  core.setHttpSessionToken("UUSFMmx4RfGONVaFl2IAVv1yN20ORd3SjLhcHfgJPys");
}
}

TEST_CASE_METHOD(TrustchainFixture, "a session of a new user can reauth")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();

  auto aliceSession = TC_AWAIT(aliceDevice.open());

  deauthSession(*aliceSession);

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "a session of a new device can reauth")
{
  auto alice = trustchain.makeUser();
  {
    auto aliceDevice = alice.makeDevice();
    auto aliceSession = TC_AWAIT(aliceDevice.open());
  }
  auto aliceDevice = alice.makeDevice();
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  deauthSession(*aliceSession);

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "a session of an existing device can reauth")
{
  auto alice = trustchain.makeUser();
  auto aliceDevice = alice.makeDevice();
  {
    auto aliceSession = TC_AWAIT(aliceDevice.open());
  }
  auto aliceSession = TC_AWAIT(aliceDevice.open());

  deauthSession(*aliceSession);

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "It can encrypt/decrypt")
{
  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "It can share explicitly with an equivalent self identity")
{
  auto alicepub = mgs::base64::decode(alice.spublicIdentity().string());
  alicepub.push_back(' ');
  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData =
                      TC_AWAIT(aliceSession->encrypt(clearData, {SPublicIdentity{mgs::base64::encode(alicepub)}})));
  std::vector<uint8_t> decryptedData;
  REQUIRE_NOTHROW(decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData)));

  REQUIRE(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt/decrypt a huge buffer with auto padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encryptedData = TC_AWAIT(aliceSession->encrypt(clearData, {}, {}, Core::ShareWithSelf::Yes, std::nullopt));
  CHECK(Encryptor::decryptedSize(encryptedData) == fiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt/decrypt a huge buffer with no padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encryptedData = TC_AWAIT(aliceSession->encrypt(clearData, {}, {}, Core::ShareWithSelf::Yes, Padding::Off));
  CHECK(Encryptor::decryptedSize(encryptedData) == almostFiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt/decrypt a huge buffer with a padding of 500")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto encryptedData = TC_AWAIT(aliceSession->encrypt(clearData, {}, {}, Core::ShareWithSelf::Yes, 500));
  CHECK(Encryptor::decryptedSize(encryptedData) % 500 == 0);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can stream encrypt/decrypt")
{
  std::vector<uint8_t> clearData(1024 * 1024 * 5);
  Crypto::randomFill(clearData);
  auto [encryptorStream, encryptorResourceId] =
      TC_AWAIT(aliceSession->makeEncryptionStream(Streams::bufferViewToInputSource(clearData)));
  auto [decryptorStream, decryptorResourceId] = TC_AWAIT(aliceSession->makeDecryptionStream(encryptorStream));

  auto decryptedData = TC_AWAIT(Streams::readAllStream(decryptorStream));
  CHECK(encryptorResourceId == decryptorResourceId);
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can stream-encrypt and decrypt")
{
  std::vector<uint8_t> clearData(1024 * 1024 * 5);
  Crypto::randomFill(clearData);
  auto [encryptorStream, encryptorResourceId] =
      TC_AWAIT(aliceSession->makeEncryptionStream(Streams::bufferViewToInputSource(clearData)));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(Core::getResourceId(encryptedData) == encryptorResourceId);
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt and stream-decrypt")
{
  auto const clearData = make_buffer("my clear data is clear");
  auto const encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));
  auto [decryptorStream, decryptorResourceId] =
      TC_AWAIT(aliceSession->makeDecryptionStream(Streams::bufferViewToInputSource(encryptedData)));

  auto decryptedData = TC_AWAIT(Streams::readAllStream(decryptorStream));
  CHECK(Core::getResourceId(encryptedData) == decryptorResourceId);
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can stream-encrypt with auto padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto [encryptorStream, encryptorResourceId] = TC_AWAIT(aliceSession->makeEncryptionStream(
      Streams::bufferViewToInputSource(clearData), {}, {}, Core::ShareWithSelf::Yes, std::nullopt));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  CHECK(Encryptor::decryptedSize(encryptedData) == fiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(Core::getResourceId(encryptedData) == encryptorResourceId);
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can stream-encrypt with no padding")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto [encryptorStream, encryptorResourceId] = TC_AWAIT(aliceSession->makeEncryptionStream(
      Streams::bufferViewToInputSource(clearData), {}, {}, Core::ShareWithSelf::Yes, Padding::Off));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  CHECK(Encryptor::decryptedSize(encryptedData) == almostFiveMiB);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(Core::getResourceId(encryptedData) == encryptorResourceId);
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can stream-encrypt with a padding of 500")
{
  std::vector<uint8_t> clearData(almostFiveMiB);
  Crypto::randomFill(clearData);
  auto [encryptorStream, encryptorResourceId] = TC_AWAIT(aliceSession->makeEncryptionStream(
      Streams::bufferViewToInputSource(clearData), {}, {}, Core::ShareWithSelf::Yes, 500));
  auto encryptedData = TC_AWAIT(Streams::readAllStream(encryptorStream));
  CHECK(Encryptor::decryptedSize(encryptedData) % 500 == 0);
  auto decryptedData = TC_AWAIT(aliceSession->decrypt(encryptedData));

  CHECK(Core::getResourceId(encryptedData) == encryptorResourceId);
  CHECK(decryptedData == clearData);
}

TEST_CASE_METHOD(TrustchainFixture, "Bob can encrypt and share with both of Alice's devices")
{
  auto const clearData = "my clear data is clear";
  auto const encryptedData = TC_AWAIT(encrypt(*bobSession, clearData, {alice.spublicIdentity()}));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession, aliceSession2}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt and share with Bob and Charlie")
{
  auto const clearData = "my clear data is clear";
  auto const encryptedData =
      TC_AWAIT(encrypt(*aliceSession, clearData, {bob.spublicIdentity(), charlie.spublicIdentity()}));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({bobSession, charlieSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can share to a duplicate user ID")
{
  auto const clearData = "my clear data is clear";
  auto const encryptedData =
      TC_AWAIT(encrypt(*aliceSession, clearData, {bob.spublicIdentity(), bob.spublicIdentity()}));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Bob can share a key he hasn't received yet")
{
  auto const clearData = "my clear data is clear";
  auto const encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {bob.spublicIdentity()}));

  TC_AWAIT(bobSession->share({TC_AWAIT(AsyncCore::getResourceId(encryptedData))}, {charlie.spublicIdentity()}, {}));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({charlieSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can encrypt without sharing with self")
{
  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData =
                      TC_AWAIT(aliceSession->encrypt(clearData, {bob.spublicIdentity()}, {}, Core::ShareWithSelf::No)));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)), Errc::InvalidArgument);
  REQUIRE_NOTHROW(TC_AWAIT(bobSession->decrypt(encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice cannot encrypt without sharing with anybody")
{
  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->encrypt(clearData, {}, {}, Core::ShareWithSelf::No)),
                                Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can stream-encrypt without sharing with self")
{
  auto const clearData = make_buffer("my clear data is clear");
  auto encryptor = TC_AWAIT(aliceSession->makeEncryptionStream(
      Streams::bufferViewToInputSource(clearData), {bob.spublicIdentity()}, {}, Core::ShareWithSelf::No));
  auto const encryptedData = TC_AWAIT(Streams::readAllStream(std::get<0>(encryptor)));
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->decrypt(encryptedData)), Errc::InvalidArgument);
  REQUIRE_NOTHROW(TC_AWAIT(bobSession->decrypt(encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice cannot stream-encrypt without sharing with anybody")
{
  auto const clearData = make_buffer("my clear data is clear");
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->makeEncryptionStream(
                                    Streams::bufferViewToInputSource(clearData), {}, {}, Core::ShareWithSelf::No)),
                                Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice shares with all her devices")
{
  auto const clearData = "my clear data is clear";
  auto const encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData));
  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession, aliceSession2}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice's second device can decrypt old resources")
{
  auto const clearData = "my clear data is clear";
  auto const encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession2}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Bob will fail to decrypt without the key")
{
  auto const clearData = make_buffer("my clear data is clear");
  auto const encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));

  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(bobSession->decrypt(encryptedData)), Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can share many resources with Bob and Charlie")
{
  auto const clearDatas = {"to be clear, ", "or not be clear, ", "that is the test case..."};

  std::vector<std::pair<std::string, std::vector<uint8_t>>> metaResources;
  metaResources.reserve(clearDatas.size());
  std::vector<SResourceId> resourceIds;
  resourceIds.reserve(clearDatas.size());
  for (auto const& clearData : clearDatas)
  {
    auto encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData));
    resourceIds.emplace_back(AsyncCore::getResourceId(encryptedData).get());
    metaResources.emplace_back(std::move(clearData), std::move(encryptedData));
  }

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->share(resourceIds, {bob.spublicIdentity(), charlie.spublicIdentity()}, {})));

  for (auto const& r : metaResources)
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({bobSession, charlieSession}, r.first, r.second)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice can share multiple times the same resource with Bob")
{
  auto const clearData = "my clear data is clear";
  auto const encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData));
  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();

  std::vector<SResourceId> resourceIds{resourceId, resourceId};

  REQUIRE_NOTHROW(TC_AWAIT(aliceSession->share(resourceIds, {bob.spublicIdentity()}, {})));

  REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({bobSession}, clearData, encryptedData)));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice cannot encrypt and share with more than 100 recipients")
{
  std::vector<SPublicIdentity> identities;
  for (int i = 0; i < 101; ++i)
    identities.push_back(trustchain.makeEmailProvisionalUser().publicIdentity);

  auto const clearData = make_buffer("my clear data is clear");
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->encrypt(clearData, identities)), Errc::InvalidArgument);

  auto const encryptedData = TC_AWAIT(aliceSession->encrypt(clearData));
  auto const resourceId = AsyncCore::getResourceId(encryptedData).get();
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->share({resourceId}, identities, {})), Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice cannot share with more than 100 `resources * recipients`")
{
  std::vector<SPublicIdentity> identities;
  for (int i = 0; i < 51; ++i)
    identities.push_back(trustchain.makeEmailProvisionalUser().publicIdentity);

  auto const clearData = make_buffer("my clear data is clear");

  std::vector<SResourceId> resourceIds;
  resourceIds.push_back(AsyncCore::getResourceId(TC_AWAIT(aliceSession->encrypt(clearData))).get());
  resourceIds.push_back(AsyncCore::getResourceId(TC_AWAIT(aliceSession->encrypt(clearData))).get());
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->share(resourceIds, identities, {})), Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "Alice cannot encrypt and share with an illformed groupId")
{
  auto const clearData = make_buffer("my clear data is clear");
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->encrypt(clearData, {}, {SGroupId{""}})), Errc::InvalidArgument);

  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->encrypt(clearData, {}, {SGroupId{"AAAA="}})),
                                Errc::InvalidArgument);

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->encrypt(clearData,
                                     {},
                                     {SGroupId{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
                                               "BBBBBBBBBBBBBBBBBBBBBBBBBBBB="}})),
      Errc::InvalidArgument);

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(aliceSession->encrypt(clearData, {}, {SGroupId{alice.spublicIdentity().string()}})),
      Errc::InvalidArgument);
}

TEST_CASE_METHOD(TrustchainFixture, "It fails to share invalid composite resource IDs")
{
  auto const sessId = Crypto::getRandom<Crypto::SimpleResourceId>();
  auto const sessKey = Crypto::getRandom<Crypto::SymmetricKey>();
  auto const resId = Crypto::getRandom<Crypto::SimpleResourceId>();
  auto id = Crypto::CompositeResourceId::newTransparentSessionId(sessId, resId);
  id[0] = 0xF0; // Mess up the composite type

  TC_AWAIT(injectStoreResourceKey(*aliceSession, sessId, sessKey));
  auto const sResourceId = SResourceId{mgs::base64::encode(id)};
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(TC_AWAIT(aliceSession->share({sResourceId}, {bob.spublicIdentity()}, {})),
                                            Errc::InvalidArgument,
                                            "unsupported composite resource ID type");
}

TEST_CASE_METHOD(TrustchainFixture, "It fails to share without the key")
{
  // Simple resource IDs
  auto simple = SResourceId{mgs::base64::encode(Crypto::getRandom<Crypto::SimpleResourceId>())};
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
      TC_AWAIT(aliceSession->share({simple}, {bob.spublicIdentity()}, {})), Errc::InvalidArgument, simple.c_str());

  // Composite resource ID
  auto composite = SResourceId{mgs::base64::encode(Crypto::CompositeResourceId::newTransparentSessionId(
      Crypto::getRandom<Crypto::SimpleResourceId>(), Crypto::getRandom<Crypto::SimpleResourceId>()))};
  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(TC_AWAIT(aliceSession->share({composite}, {bob.spublicIdentity()}, {})),
                                            Errc::InvalidArgument,
                                            composite.c_str());
}

TEST_CASE_METHOD(TrustchainFixture, "Sharing a transparent session")
{
  auto const clearData = make_buffer("crystal clear");
  std::vector<uint8_t> encryptedData;
  auto const session = TC_AWAIT(aliceSession->makeEncryptionSession());
  auto const sessionId = session.resourceId();
  auto const sessionKey = session.sessionKey();
  auto const subkeySeed = Crypto::getRandom<Crypto::SubkeySeed>();

  SECTION("It can share with the v9 encryption format")
  {
    encryptedData = std::vector<uint8_t>(EncryptorV9::encryptedSize(clearData.size()));
    TC_AWAIT(EncryptorV9::encrypt(encryptedData, clearData, sessionId, sessionKey, subkeySeed));
  }

  SECTION("It can share with the v10 encryption format")
  {
    encryptedData = std::vector<uint8_t>(EncryptorV10::encryptedSize(clearData.size(), {}));
    TC_AWAIT(EncryptorV10::encrypt(encryptedData, clearData, sessionId, sessionKey, subkeySeed, {}));
  }

  SECTION("It can share with the v11 encryption format")
  {
    encryptedData = std::vector<uint8_t>(EncryptorV11::encryptedSize(clearData.size(), {}));
    TC_AWAIT(EncryptorV11::encrypt(encryptedData, clearData, sessionId, sessionKey, subkeySeed, {}));
  }

  // Share the transparent session with Bob
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(bobSession->decrypt(encryptedData)), Errc::InvalidArgument);

  TC_AWAIT(injectStoreResourceKey(*bobSession, sessionId, sessionKey));
  auto const decrypted = TC_AWAIT(bobSession->decrypt(encryptedData));
  REQUIRE(decrypted == clearData);

  // Share the individual resource with Charlie
  TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(charlieSession->decrypt(encryptedData)), Errc::InvalidArgument);

  auto const resourceId = Core::getResourceId(encryptedData);
  auto const sResourceId = SResourceId{mgs::base64::encode(resourceId)};
  TC_AWAIT(aliceSession->share({sResourceId}, {charlie.spublicIdentity()}, {}));
  auto const decryptedIndividual = TC_AWAIT(charlieSession->decrypt(encryptedData));
  REQUIRE(decryptedIndividual == clearData);

  // Charlie can reshare the individual resource without knowing the session
  auto const groupId = TC_AWAIT(charlieSession->createGroup({charlie.spublicIdentity()}));
  TC_AWAIT(charlieSession->share({sResourceId}, {}, {groupId}));
}

TEST_CASE_METHOD(TrustchainFixture, "session token (2FA)")
{
  SECTION("Alice can use verifyIdentity when Ready to get a session token")
  {
    auto const aliceEmail = Email{"alice456.test@tanker.io"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));
    auto aliceVerificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
    auto emailVerif = Verification::ByEmail{aliceEmail, VerificationCode{aliceVerificationCode}};
    TC_AWAIT(aliceSession->registerIdentity(emailVerif));
    REQUIRE(aliceSession->status() == Status::Ready);

    auto withToken = Core::VerifyWithToken::Yes;
    aliceVerificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
    emailVerif = Verification::ByEmail{aliceEmail, VerificationCode{aliceVerificationCode}};
    auto token = TC_AWAIT(aliceSession->verifyIdentity(emailVerif, withToken));
    CHECK(token.has_value());
  }

  SECTION("Alice can use setVerificationMethod with email to get a session token")
  {
    auto const aliceEmail = Email{"alice@wonder.land"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));
    auto const passVerif = Passphrase("testpass");
    TC_AWAIT(aliceSession->registerIdentity(passVerif));

    auto const aliceVerificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
    auto const emailVerif = Verification::ByEmail{aliceEmail, VerificationCode{aliceVerificationCode}};

    auto withToken = Core::VerifyWithToken::Yes;
    auto token = TC_AWAIT(aliceSession->setVerificationMethod(emailVerif, withToken));
    CHECK(token.has_value());
  }

  SECTION(
      "Alice can use setVerificationMethod with phone number to get a session "
      "token")
  {
    auto const alicePhoneNumber = makePhoneNumber();
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));
    auto const passVerif = Passphrase("testpass");
    TC_AWAIT(aliceSession->registerIdentity(passVerif));

    auto const aliceVerificationCode = TC_AWAIT(getVerificationCode(alicePhoneNumber));
    auto const phoneNumberVerif =
        Verification::ByPhoneNumber{alicePhoneNumber, VerificationCode{aliceVerificationCode}};

    auto withToken = Core::VerifyWithToken::Yes;
    auto token = TC_AWAIT(aliceSession->setVerificationMethod(phoneNumberVerif, withToken));
    CHECK(token.has_value());
  }

  SECTION("Alice can get a session token after registerIdentity with an email")
  {
    auto const aliceEmail = Email{"alice123.test@tanker.io"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));
    auto const aliceVerificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
    auto const emailVerif = Verification::ByEmail{aliceEmail, VerificationCode{aliceVerificationCode}};

    auto withToken = Core::VerifyWithToken::Yes;
    auto token = TC_AWAIT(aliceSession->registerIdentity(emailVerif, withToken));
    CHECK(token.has_value());
    CHECK(mgs::base64::decode(*token).size() > 0);
  }

  SECTION("Alice can get a session token after registerIdentity with a passphrase")
  {
    auto const alicePass = Passphrase{"alicealice"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));

    auto withToken = Core::VerifyWithToken::Yes;
    auto token = TC_AWAIT(aliceSession->registerIdentity(alicePass, withToken));
    CHECK(token.has_value());
  }

  SECTION(
      "Cannot get a session token after registerIdentity with a verification "
      "key")
  {
    auto const aliceEmail = Email{"alice@wonder.land"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));

    auto withToken = Core::VerifyWithToken::Yes;
    auto verificationKey = TC_AWAIT(aliceSession->generateVerificationKey());
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(aliceSession->registerIdentity(verificationKey, withToken)),
                                  Errc::InvalidArgument);
  }

  SECTION("Can check a session token with the REST API")
  {
    auto const alicePass = Passphrase{"alicealice"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));

    auto withToken = Core::VerifyWithToken::Yes;
    auto sessionToken = TC_AWAIT(aliceSession->registerIdentity(alicePass, withToken));

    std::string expectedMethod = "passphrase";
    auto method = TC_AWAIT(checkSessionToken(trustchain.id,
                                             TestConstants::verificationApiToken(),
                                             alice.spublicIdentity().string(),
                                             *sessionToken,
                                             expectedMethod));
    CHECK(method == expectedMethod);
  }

  SECTION("Fails to check a session token with the wrong method")
  {
    auto const alicePass = Passphrase{"alicealice"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));

    auto withToken = Core::VerifyWithToken::Yes;
    auto sessionToken = TC_AWAIT(aliceSession->registerIdentity(alicePass, withToken));

    std::string wrongMethod = "oidc_id_token";
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(checkSessionToken(trustchain.id,
                                                             TestConstants::verificationApiToken(),
                                                             alice.spublicIdentity().string(),
                                                             *sessionToken,
                                                             wrongMethod)),
                                  Errc::InvalidArgument);
  }

  SECTION("Fails to check an invalid session token")
  {
    auto const alicePass = Passphrase{"alicealice"};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));

    auto withToken = Core::VerifyWithToken::Yes;
    TC_AWAIT(aliceSession->registerIdentity(alicePass, withToken));
    std::string sessionToken = "This ain't a valid token";

    std::string verifMethod = "passphrase";
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(checkSessionToken(trustchain.id,
                                                             TestConstants::verificationApiToken(),
                                                             alice.spublicIdentity().string(),
                                                             sessionToken,
                                                             verifMethod)),
                                  Errc::InvalidArgument);
  }

  SECTION("Can check a session token with multiple allowed methods")
  {
    auto const aliceEmail = Email{"aaalice@tanker.io"};
    auto const verificationCode = TC_AWAIT(getVerificationCode(aliceEmail));
    auto const emailVerif = Verification::ByEmail{aliceEmail, VerificationCode{verificationCode}};
    auto alice = trustchain.makeUser();
    auto aliceDevice = alice.makeDevice();
    auto const aliceSession = aliceDevice.createCore();
    TC_AWAIT(aliceSession->start(alice.identity));

    auto withToken = Core::VerifyWithToken::Yes;
    auto sessionToken = TC_AWAIT(aliceSession->registerIdentity(emailVerif, withToken));

    nlohmann::json expectedMethods = {
        {{"type", "passphrase"}},
        {{"type", "email"}, {"email", aliceEmail.string()}},
    };
    auto method = TC_AWAIT(checkSessionToken(trustchain.id,
                                             TestConstants::verificationApiToken(),
                                             alice.spublicIdentity().string(),
                                             *sessionToken,
                                             expectedMethods));
    CHECK(method == "email");
  }
}

TEST_CASE_METHOD(TrustchainFixture, "Alice cannot share with identity from a different trustchain")
{
  auto otherTrustchain = TC_AWAIT(trustchainFactory().createTrustchain("sdk-native-functional-tests-other-trustchain"));
  auto eve = otherTrustchain->makeEmailProvisionalUser();

  auto const clearData = "my clear data is clear";
  std::vector<uint8_t> encryptedData;
  REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(make_buffer(clearData))));

  auto resourceId = TC_AWAIT(AsyncCore::getResourceId(encryptedData));

  TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(TC_AWAIT(aliceSession->share({resourceId}, {eve.publicIdentity}, {})),
                                            Errors::Errc::InvalidArgument,
                                            "public identity not in the trustchain");

  TC_AWAIT(trustchainFactory().deleteTrustchain(otherTrustchain->id));
}

TEST_CASE_METHOD(TrustchainFixture, "Alice has network issues", "[net]")
{
  auto device1 = alice.makeDevice();

  auto const clearData = make_buffer("my clear data is clear");
  std::vector<uint8_t> encryptedData;
  {
    auto core = TC_AWAIT(device1.open());
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(core->encrypt(clearData, {bob.spublicIdentity()})));
  }
  auto core = Functional::makeAsyncCore(
      "https://no-api.tanker.io", device1.getSdkInfo(), device1.writablePath(), device1.writablePath());

  auto const status = TC_AWAIT(core->start(device1.identity()));
  SECTION("Can open a Session [VDTNXV]")
  {
    REQUIRE(status == Tanker::Status::Ready);
  }
  SECTION("Can decrypt a resource offline [FMHLH4]")
  {
    auto const decrypted = TC_AWAIT(core->decrypt(encryptedData));
    REQUIRE(decrypted == clearData);
  }
  SECTION("Throws if trying to encrypt [AFOZAL]")
  {
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->encrypt(clearData)), Errors::Errc::NetworkError);
  }
  SECTION("Throws if trying to decrypt without the key [0MYRMO]")
  {
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(aliceSession->encrypt(clearData)));
    TANKER_CHECK_THROWS_WITH_CODE(TC_AWAIT(core->decrypt(encryptedData)), Errors::Errc::NetworkError);
  }
}

inline auto constexpr simpleEncryptionOverhead = 49;
inline auto constexpr paddedSimpleEncryptionOverhead = simpleEncryptionOverhead + 1;

TEST_CASE_METHOD(TrustchainFixture, "Alice can use the padding encryption option")
{
  SECTION("encrypt/decrypt with auto padding")
  {
    std::string const clearData("my clear data is clear!");
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {}, {}, std::nullopt)));

    auto const lengthWithPadme = 24;
    REQUIRE(encryptedData.size() - paddedSimpleEncryptionOverhead == lengthWithPadme);
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION("encrypt/decrypt with no padding")
  {
    std::string const clearData("my clear data is clear!");
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {}, {}, Padding::Off)));

    REQUIRE(encryptedData.size() - simpleEncryptionOverhead == clearData.size());
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION("encrypt/decrypt with a padding step")
  {
    std::string const clearData("my clear data is clear!");
    auto const step = 13;
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {}, {}, step)));

    REQUIRE((encryptedData.size() - paddedSimpleEncryptionOverhead) % step == 0);
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }

  SECTION("encrypt/decrypt with a huge padding step should select the v11 format")
  {
    std::string const clearData("my clear data is clear!");
    auto const step = 2 * 1024 * 1024;
    std::vector<uint8_t> encryptedData;
    REQUIRE_NOTHROW(encryptedData = TC_AWAIT(encrypt(*aliceSession, clearData, {}, {}, step)));

    CHECK(encryptedData[0] == 11);
    REQUIRE_NOTHROW(TC_AWAIT(checkDecrypt({aliceSession}, clearData, encryptedData)));
  }
}
