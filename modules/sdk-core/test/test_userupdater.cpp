#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Users/Updater.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <Tanker/Verif/Helpers.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/TransformTo.hpp>

#include <gsl-lite.hpp>

#include <doctest.h>

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
      Test::transformTo<std::vector<Trustchain::UserAction>>(alice.entries());
  auto const revokedEntry1 = revokeADeviceGetAnEntry(aliceEntries, alice);
  aliceEntries.push_back(revokedEntry1);
  aliceEntries.push_back(revokeADeviceGetAnEntry(aliceEntries, alice));
  auto const selfdevice = alice.addDevice();
  aliceEntries.push_back(selfdevice.action);
  auto const revokedEntry2 = revokeADeviceGetAnEntry(aliceEntries, alice);
  aliceEntries.push_back(revokedEntry2);
  aliceEntries.push_back(alice.addDevice().action);
  aliceEntries.push_back(revokeADeviceGetAnEntry(aliceEntries, alice));

  SUBCASE("Should find the trustchainID")
  {
    REQUIRE_NOTHROW(Updater::extractTrustchainSignature(
        generator.context().id(), generator.rootBlock()));
    auto const sig = Updater::extractTrustchainSignature(
        generator.context().id(), generator.rootBlock());
    CHECK_EQ(sig, generator.trustchainSigKp().publicKey);
  }

  SUBCASE("extract an encrypted user key")
  {
    SUBCASE("from our device")
    {
      auto const encUserKey =
          Updater::extractEncryptedUserKey(selfdevice.action);
      REQUIRE_UNARY(encUserKey.has_value());
      auto const dev = selfdevice.action.get<Actions::DeviceCreation::v3>();
      auto const [publicUserKey, sealedPrivateKey] = *encUserKey;
      CHECK_EQ(sealedPrivateKey, dev.sealedPrivateUserEncryptionKey());
      CHECK_EQ(
          encUserKey.value(),
          SealedEncryptionKeyPair{{}, dev.sealedPrivateUserEncryptionKey()});
    }

    SUBCASE("from a revocation before our device")
    {
      auto const encUserKey =
          Updater::extractEncryptedUserKey(revokedEntry1, selfdevice.id());
      REQUIRE_UNARY(encUserKey.has_value());
      CHECK_EQ(
          encUserKey.value(),
          SealedEncryptionKeyPair{revokedEntry1.previousPublicEncryptionKey(),
                                  revokedEntry1.sealedKeyForPreviousUserKey()});
    }

    SUBCASE("from a revocation after our device")
    {
      auto const encUserKey =
          Updater::extractEncryptedUserKey(revokedEntry2, selfdevice.id());
      REQUIRE_UNARY(encUserKey.has_value());

      auto const encryptedKey =
          Tanker::Revocation::findUserKeyFromDeviceSealedKeys(
              selfdevice.id(), revokedEntry2.sealedUserKeysForDevices());
      CHECK_EQ(encUserKey.value(),
               SealedEncryptionKeyPair{revokedEntry2.publicEncryptionKey(),
                                       *encryptedKey});
    }
  }

  SUBCASE("processing server entries for the user")
  {
    auto const [user, sealedKeys] = Updater::processUserSealedKeys(
        selfdevice.keys(), generator.context(), aliceEntries);
    CHECK_EQ(sealedKeys.size(), 5);

    SUBCASE("recovering keys")
    {
      auto const userKeys = Updater::recoverUserKeys(
          selfdevice.keys().encryptionKeyPair, sealedKeys);
      CHECK_EQ(userKeys.size(), 5);
      CHECK_EQ(userKeys.back(), alice.userKeys().back());
    }
  }
}
