#include "TrustchainBuilder.hpp"

#include <Helpers/UniquePath.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainStore.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Messages.hpp>
#include <Tanker/Unlock/Registration.hpp>

#include <Helpers/Buffers.hpp>

#include <nlohmann/json.hpp>

#include <doctest.h>

#include "TestVerifier.hpp"

using namespace std::string_literals;

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace
{
void checkUnlockMessage(Trustchain::TrustchainId const& tid,
                        Crypto::PublicSignatureKey const& key,
                        Unlock::Message const& message)
{
  auto jmessage = nlohmann::json(message);
  auto const message2 = Unlock::Message{jmessage};

  FAST_CHECK_EQ(message2.trustchainId, message.trustchainId);
  FAST_CHECK_EQ(message2.deviceId, message.deviceId);
  FAST_CHECK_EQ(tid, message.trustchainId);
  FAST_CHECK_UNARY(
      Crypto::verify(message2.signData(), message2.signature, key));
}
}

TEST_CASE("it can convert a ghost device to unlock key")
{
  auto const ghostDevice = GhostDevice{
      make<Crypto::PrivateSignatureKey>("sigkey"),
      make<Crypto::PrivateEncryptionKey>("enckey"),
  };
  auto const gotGhostDevice = GhostDevice::create(
      VerificationKey{"eyJkZXZpY2VJZCI6IlpHVjJhV1FBQUFBQUFBQUFBQUFBQUF"
                      "BQUFBQUFBQUFBQUFBQUFBQU"
                      "FBQUE9IiwicHJpdmF0ZVNpZ25hdHVyZUtleSI6ImMybG5hM"
                      "lY1QUFBQUFBQUFBQUFBQUFB"
                      "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF"
                      "BQUFBQUFBQUFBQUFBQUFBQU"
                      "FBQUFBQUFBQUFBPT0iLCJwcml2YXRlRW5jcnlwdGlvbktle"
                      "SI6IlpXNWphMlY1QUFBQUFB"
                      "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9In0="});
  CHECK(ghostDevice == gotGhostDevice);
}

TEST_CASE("verificationKey")
{
  SUBCASE("extract")
  {
    REQUIRE_THROWS_AS(GhostDevice::create(VerificationKey{"plop"}),
                      Error::InvalidVerificationKey);
  }

  TrustchainBuilder builder;
  builder.makeUser("alice");
  auto const alice = builder.getUser("alice").value();
  auto const aliceUserSecret =
      make<Crypto::SymmetricKey>("this is alice's userSecret");
  auto const firstDev = alice.devices.front();
  std::unique_ptr<Unlock::Registration> reg{nullptr};
  auto const& aliceKeys = alice.userKeys.back();
  auto ghostDeviceKeys = DeviceKeys::create();
  reg =
      Unlock::generate(alice.userId,
                       aliceKeys.keyPair,
                       BlockGenerator(builder.trustchainId(),
                                      firstDev.keys.signatureKeyPair.privateKey,
                                      firstDev.id),
                       ghostDeviceKeys);
  auto const password = Password{"some secret"};
  auto const email = Email{"alice@aol.com"};
  auto const message =
      Unlock::Message(builder.trustchainId(),
                      firstDev.id,
                      Unlock::Verification{password},
                      aliceUserSecret,
                      firstDev.keys.signatureKeyPair.privateKey);
  FAST_REQUIRE_UNARY(reg);
  FAST_REQUIRE_UNARY_FALSE(reg->verificationKey.empty());
  SUBCASE("generate")
  {
    REQUIRE_NOTHROW(GhostDevice::create(reg->verificationKey));
    auto const gh = GhostDevice::create(reg->verificationKey);
    FAST_CHECK_EQ(gh.privateEncryptionKey,
                  ghostDeviceKeys.encryptionKeyPair.privateKey);
    FAST_CHECK_EQ(gh.privateSignatureKey,
                  ghostDeviceKeys.signatureKeyPair.privateKey);
    auto ghostDeviceEntry = toVerifiedEntry(
        blockToServerEntry(Serialization::deserialize<Block>(reg->block)));
    auto const dc = ghostDeviceEntry.action.get<DeviceCreation>();
    FAST_CHECK_EQ(ghostDeviceKeys.encryptionKeyPair.publicKey,
                  dc.publicEncryptionKey());
    FAST_CHECK_EQ(ghostDeviceKeys.signatureKeyPair.publicKey,
                  dc.publicSignatureKey());
    FAST_CHECK_UNARY(dc.isGhostDevice());
    FAST_CHECK_EQ(alice.userId, dc.userId());
  }

  SUBCASE("serialization/unserialization of message")
  {
    checkUnlockMessage(builder.trustchainId(),
                       firstDev.keys.signatureKeyPair.publicKey,
                       message);
  }

  SUBCASE("createValidatedDevice")
  {
    auto const gh = GhostDevice::create(reg->verificationKey);
    auto const encryptedPrivateKey =
        Crypto::sealEncrypt<Crypto::SealedPrivateEncryptionKey>(
            aliceKeys.keyPair.privateKey,
            ghostDeviceKeys.encryptionKeyPair.publicKey);

    EncryptedUserKey ec{make<Trustchain::DeviceId>("devid"),
                        encryptedPrivateKey};

    auto newDeviceKeys = DeviceKeys::create();
    auto const validatedDevice = Unlock::createValidatedDevice(
        builder.trustchainId(), alice.userId, gh, newDeviceKeys, ec);
    auto const validatedDeviceEntry =
        toVerifiedEntry(blockToServerEntry(validatedDevice));
    auto const vdc = validatedDeviceEntry.action.get<DeviceCreation>();
    REQUIRE(vdc.holds_alternative<DeviceCreation::v3>());
    auto const& dc3 = vdc.get<DeviceCreation::v3>();
    auto const userKey = dc3.sealedPrivateUserEncryptionKey();
    REQUIRE(!userKey.is_null());

    auto const privateEncryptionKey =
        Crypto::sealDecrypt(userKey, newDeviceKeys.encryptionKeyPair);

    REQUIRE_EQ(privateEncryptionKey, aliceKeys.keyPair.privateKey);
    REQUIRE_EQ(dc3.publicEncryptionKey(),
               newDeviceKeys.encryptionKeyPair.publicKey);
    REQUIRE_EQ(dc3.publicSignatureKey(),
               newDeviceKeys.signatureKeyPair.publicKey);
    REQUIRE_EQ(alice.userId, dc3.userId());
    REQUIRE_EQ(false, dc3.isGhostDevice());
  }
}
