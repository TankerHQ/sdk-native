#include <Tanker/Revocation.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Users/Updater.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <Tanker/Verif/Helpers.hpp>

#include <Helpers/Await.hpp>

#include <gsl/gsl-lite.hpp>

#include <range/v3/range/conversion.hpp>

#include <catch2/catch.hpp>

#include "TrustchainGenerator.hpp"

namespace Updater = Tanker::Users::Updater;
namespace Actions = Tanker::Trustchain::Actions;

using namespace Tanker;
using Tanker::Crypto::SealedEncryptionKeyPair;

namespace
{
auto revokeADeviceGetAnEntry(std::vector<Trustchain::UserAction>& entries,
                             Tanker::Test::User& user)
{
  auto& target = user.addDevice();
  entries.push_back(target.action);
  return user.revokeDevice(target);
}
}

TEST_CASE("UserUpdater")
{
  Tanker::Test::Generator generator;
  auto alice = generator.makeUser("Alice");
  auto aliceEntries =
      alice.entries() | ranges::to<std::vector<Trustchain::UserAction>>;
  auto const revokedEntry1 = revokeADeviceGetAnEntry(aliceEntries, alice);
  aliceEntries.push_back(revokedEntry1);
  aliceEntries.push_back(revokeADeviceGetAnEntry(aliceEntries, alice));
  auto const selfdevice = alice.addDevice();
  aliceEntries.push_back(selfdevice.action);
  auto const revokedEntry2 = revokeADeviceGetAnEntry(aliceEntries, alice);
  aliceEntries.push_back(revokedEntry2);
  aliceEntries.push_back(alice.addDevice().action);
  aliceEntries.push_back(revokeADeviceGetAnEntry(aliceEntries, alice));

  SECTION("Should find the trustchainID")
  {
    REQUIRE_NOTHROW(Updater::extractTrustchainSignature(
        generator.context().id(), generator.rootBlock()));
    auto const sig = Updater::extractTrustchainSignature(
        generator.context().id(), generator.rootBlock());
    CHECK(sig == generator.trustchainSigKp().publicKey);
  }

  SECTION("extract an encrypted user key")
  {
    SECTION("from our device")
    {
      auto const encUserKey =
          Updater::extractEncryptedUserKey(selfdevice.action);
      REQUIRE(encUserKey.has_value());
      auto const dev = selfdevice.action.get<Actions::DeviceCreation::v3>();
      auto const [publicUserKey, sealedPrivateKey] = *encUserKey;
      CHECK(sealedPrivateKey == dev.sealedPrivateUserEncryptionKey());
      CHECK(encUserKey.value() ==
            SealedEncryptionKeyPair{{}, dev.sealedPrivateUserEncryptionKey()});
    }

    SECTION("from a revocation before our device")
    {
      auto const encUserKey =
          Updater::extractEncryptedUserKey(revokedEntry1, selfdevice.id());
      REQUIRE(encUserKey.has_value());
      CHECK(
          encUserKey.value() ==
          SealedEncryptionKeyPair{revokedEntry1.previousPublicEncryptionKey(),
                                  revokedEntry1.sealedKeyForPreviousUserKey()});
    }

    SECTION("from a revocation after our device")
    {
      auto const encUserKey =
          Updater::extractEncryptedUserKey(revokedEntry2, selfdevice.id());
      REQUIRE(encUserKey.has_value());

      auto const encryptedKey =
          Tanker::Revocation::findUserKeyFromDeviceSealedKeys(
              selfdevice.id(), revokedEntry2.sealedUserKeysForDevices());
      CHECK(encUserKey.value() ==
            SealedEncryptionKeyPair{revokedEntry2.publicEncryptionKey(),
                                    *encryptedKey});
    }
  }

  SECTION("processing server entries for the user")
  {
    auto const [user, sealedKeys] = Updater::processUserSealedKeys(
        selfdevice.id(), selfdevice.keys(), generator.context(), aliceEntries);
    CHECK(sealedKeys.size() == 5);

    SECTION("recovering keys")
    {
      auto const userKeys = Updater::recoverUserKeys(
          selfdevice.keys().encryptionKeyPair, sealedKeys);
      CHECK(userKeys.size() == 5);
      CHECK(userKeys == alice.userKeys());
    }
  }
}
