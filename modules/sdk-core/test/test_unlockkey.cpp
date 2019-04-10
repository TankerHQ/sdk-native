#include "TrustchainBuilder.hpp"

#include <Helpers/UniquePath.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Trustchain.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Unlock/Create.hpp>
#include <Tanker/Unlock/Messages.hpp>
#include <Tanker/Unlock/Options.hpp>
#include <Tanker/Unlock/Registration.hpp>
#include <Tanker/UnverifiedEntry.hpp>

#include <Helpers/Buffers.hpp>

#include <nlohmann/json.hpp>

#include <doctest.h>

#include "TestVerifier.hpp"

using namespace std::string_literals;

namespace Tanker
{
auto const someUnlockKey = UnlockKey{
    "eyJkZXZpY2VJZCI6IlFySHhqNk9qSURBUmJRVWdBenRmUHZyNFJVZUNRWDRhb1ZTWXJiSzNEa2"
    "s9IiwicHJpdmF0ZUVuY3J5cHRpb25LZXkiOiJQTnRjNEFXMWZ5NnBnbVd2SlA5RTN0ZytxMFJ0"
    "emkxdlcvSEFqQnBMRmdnPSIsInByaXZhdGVTaWduYXR1cmVLZXkiOiJxbXBNZmlHRHYweEZyVD"
    "dMVHZjTkFYQ2FrbFRWcE54Y1ByRjdycStKelhuZ2dleUo1YnR2YUlrWDlURmxMQjdKaU5ObmVo"
    "dXJjZEhRU05xMEgzQlJidz09In0="};

namespace
{
void checkUnlockMessage(TrustchainId const& tid,
                        Email const& email,
                        Password const& password,
                        Crypto::PublicSignatureKey const& key,
                        Unlock::Message const& message)
{
  auto jmessage = nlohmann::json(message);
  auto const message2 = Unlock::Message{jmessage};

  FAST_CHECK_EQ(message2.trustchainId, message.trustchainId);
  FAST_CHECK_EQ(message2.deviceId, message.deviceId);
  FAST_CHECK_EQ(tid, message.trustchainId);
  FAST_CHECK_EQ(email, message.claims.email);
  FAST_CHECK_EQ(
      Crypto::generichash(gsl::make_span(password).as_span<uint8_t const>()),
      message.claims.password);
  FAST_CHECK_UNARY(
      Crypto::verify(message2.signData(), message2.signature, key));
}
}

TEST_CASE("it can convert a ghost device to unlock key")
{
  auto const ghostDevice = GhostDevice{
      make<DeviceId>("devid"),
      make<Crypto::PrivateSignatureKey>("sigkey"),
      make<Crypto::PrivateEncryptionKey>("enckey"),
  };
  auto const gotGhostDevice = Unlock::extract(
      UnlockKey{"eyJkZXZpY2VJZCI6IlpHVjJhV1FBQUFBQUFBQUFBQUFBQUF"
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

TEST_CASE("UpdateOptions")
{
  auto locker = Unlock::UpdateOptions{}.set(Password{"keep it secret"});
  SUBCASE("only set password")
  {
    FAST_REQUIRE_EQ(locker.get<Password>().value().string(), "keep it secret");
    FAST_REQUIRE_UNARY_FALSE(locker.get<Email>());
    FAST_REQUIRE_UNARY_FALSE(locker.get<UnlockKey>());
  }
  SUBCASE("set Email too")
  {
    locker.set(Email{"germaine@yahou.fr"});
    FAST_REQUIRE_EQ(locker.get<Password>().value().string(), "keep it secret");
    FAST_REQUIRE_EQ(locker.get<Email>().value().string(), "germaine@yahou.fr");
    FAST_REQUIRE_UNARY_FALSE(locker.get<UnlockKey>());
  }
  SUBCASE("unset password")
  {
    locker.set(Email{"germaine@yahou.fr"});
    locker.reset<Password>();
    FAST_REQUIRE_UNARY_FALSE(locker.get<Password>());
    FAST_REQUIRE_EQ(locker.get<Email>().value().string(), "germaine@yahou.fr");
    FAST_REQUIRE_UNARY_FALSE(locker.get<UnlockKey>());
  }
}

TEST_CASE("unlockKey")
{
  SUBCASE("extract")
  {
    REQUIRE_THROWS_AS(Unlock::extract(UnlockKey{"plop"}),
                      Error::InvalidUnlockKey);
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
                                      firstDev.keys.deviceId),
                       ghostDeviceKeys);
  auto const password = Password{"some secret"};
  auto const email = Email{"alice@aol.com"};
  auto const message =
      Unlock::Message(builder.trustchainId(),
                      firstDev.keys.deviceId,
                      Unlock::UpdateOptions{email, password, someUnlockKey},
                      aliceUserSecret,
                      firstDev.keys.signatureKeyPair.privateKey);
  FAST_REQUIRE_UNARY(reg);
  FAST_REQUIRE_UNARY_FALSE(reg->unlockKey.empty());
  SUBCASE("generate")
  {
    REQUIRE_NOTHROW(Unlock::extract(reg->unlockKey));
    auto const gh = Unlock::extract(reg->unlockKey);
    FAST_CHECK_EQ(gh.privateEncryptionKey,
                  ghostDeviceKeys.encryptionKeyPair.privateKey);
    FAST_CHECK_EQ(gh.privateSignatureKey,
                  ghostDeviceKeys.signatureKeyPair.privateKey);
    auto ghostDeviceEntry = toVerifiedEntry(
        blockToUnverifiedEntry(Serialization::deserialize<Block>(reg->block)));
    auto const dc =
        mpark::get<DeviceCreation>(ghostDeviceEntry.action.variant());
    FAST_CHECK_EQ(gh.deviceId.base(), ghostDeviceEntry.hash.base());
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
                       email,
                       password,
                       firstDev.keys.signatureKeyPair.publicKey,
                       message);
  }

  SUBCASE("extact unlock message")
  {
    auto const unlockKeyRes = message.claims.getUnlockKey(aliceUserSecret);
    CHECK_EQ(unlockKeyRes, someUnlockKey);
  }

  SUBCASE("createValidatedDevice")
  {
    auto const gh = Unlock::extract(reg->unlockKey);
    auto const encryptedPrivateKey =
        Crypto::SealedPrivateEncryptionKey{gsl::make_span(
            Crypto::sealEncrypt(aliceKeys.keyPair.privateKey,
                                ghostDeviceKeys.encryptionKeyPair.publicKey))};

    EncryptedUserKey ec{aliceKeys.keyPair.publicKey, encryptedPrivateKey};

    auto newDeviceKeys = DeviceKeys::create();
    auto const validatedDevice = Unlock::createValidatedDevice(
        builder.trustchainId(), alice.userId, gh, newDeviceKeys, ec);
    auto const validatedDeviceEntry = toVerifiedEntry(blockToUnverifiedEntry(
        Serialization::deserialize<Block>(validatedDevice)));
    auto const vdc =
        mpark::get<DeviceCreation>(validatedDeviceEntry.action.variant());
    REQUIRE(vdc.userKeyPair().has_value());
    auto const userKey =
        vdc.userKeyPair().value().encryptedPrivateEncryptionKey;
    REQUIRE(!userKey.is_null());

    auto const privateEncryptionKey =
        Crypto::sealDecrypt<Crypto::PrivateEncryptionKey>(
            userKey, newDeviceKeys.encryptionKeyPair);

    REQUIRE_EQ(privateEncryptionKey, aliceKeys.keyPair.privateKey);
    REQUIRE_EQ(vdc.publicEncryptionKey(),
               newDeviceKeys.encryptionKeyPair.publicKey);
    REQUIRE_EQ(vdc.publicSignatureKey(),
               newDeviceKeys.signatureKeyPair.publicKey);
    REQUIRE_EQ(alice.userId, vdc.userId());
    REQUIRE_EQ(gh.deviceId.base(), validatedDeviceEntry.author.base());
    REQUIRE_EQ(false, vdc.isGhostDevice());
  }
}
}
