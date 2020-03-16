#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Users/Updater.hpp>

#include <Tanker/Verif/Helpers.hpp>

#include "TrustchainBuilder.hpp"
#include <Helpers/Await.hpp>

#include <gsl-lite.hpp>

#include <doctest.h>

namespace Updater = Tanker::Users::Updater;
namespace Actions = Tanker::Trustchain::Actions;

using Tanker::Crypto::SealedEncryptionKeyPair;

namespace
{
auto revokeADeviceGetAnEntry(TrustchainBuilder& builder,
                             TrustchainBuilder::Device const& source)
{
  auto const target = builder.makeDevice("Alice");
  builder.revokeDevice2(source, target.device);
  return builder.entries().back();
}
}

TEST_CASE("UserUpdater")
{
  auto const dbPtr = AWAIT(Tanker::DataStore::createDatabase(":memory:"));
  TrustchainBuilder builder;
  auto const user1 = builder.makeUser("Alice");
  auto const revokedEntry1 =
      revokeADeviceGetAnEntry(builder, user1.user.devices.front());
  revokeADeviceGetAnEntry(builder, user1.user.devices.front());
  auto const selfdevice = builder.makeDevice("Alice");
  auto const revokedEntry2 =
      revokeADeviceGetAnEntry(builder, user1.user.devices.front());
  auto const device3 = builder.makeDevice("Alice");
  revokeADeviceGetAnEntry(builder, user1.user.devices.front());

  using Tanker::Verif::makeVerifiedEntry;
  SUBCASE("Should find the trustchainID")
  {
    REQUIRE_NOTHROW(Updater::extractTrustchainSignature(
        builder.trustchainId(), builder.entries().front()));
    auto const sig = Updater::extractTrustchainSignature(
        builder.trustchainId(), builder.entries().front());
    CHECK_EQ(sig, builder.trustchainPublicKey());
  }

  SUBCASE("extract an encrypted user key")
  {
    SUBCASE("from our device")
    {
      auto const encUserKey = Updater::extractEncryptedUserKey(
          *makeVerifiedEntry(selfdevice.entry)
               .action.get_if<Actions::DeviceCreation>());
      REQUIRE_UNARY(encUserKey.has_value());
      auto const dev = selfdevice.entry.action()
                           .get<Actions::DeviceCreation>()
                           .get<Actions::DeviceCreation::v3>();
      auto const [publicUserKey, sealedPrivateKey] = *encUserKey;
      CHECK_EQ(sealedPrivateKey, dev.sealedPrivateUserEncryptionKey());
      CHECK_EQ(
          encUserKey.value(),
          SealedEncryptionKeyPair{{}, dev.sealedPrivateUserEncryptionKey()});
    }

    SUBCASE("from a revocation before our device")
    {
      auto const encUserKey = Updater::extractEncryptedUserKey(
          *makeVerifiedEntry(revokedEntry1)
               .action.get_if<Actions::DeviceRevocation>(),
          selfdevice.device.id);
      REQUIRE_UNARY(encUserKey.has_value());
      auto const dev = revokedEntry1.action()
                           .get<Actions::DeviceRevocation>()
                           .get<Actions::DeviceRevocation::v2>();
      CHECK_EQ(encUserKey.value(),
               SealedEncryptionKeyPair{dev.previousPublicEncryptionKey(),
                                       dev.sealedKeyForPreviousUserKey()});
    }

    SUBCASE("from a revocation after our device")
    {
      auto const encUserKey = Updater::extractEncryptedUserKey(
          *makeVerifiedEntry(revokedEntry2)
               .action.get_if<Actions::DeviceRevocation>(),
          selfdevice.device.id);
      REQUIRE_UNARY(encUserKey.has_value());
      auto const dev = revokedEntry2.action()
                           .get<Actions::DeviceRevocation>()
                           .get<Actions::DeviceRevocation::v2>();

      auto const encryptedKey =
          Tanker::Revocation::findUserKeyFromDeviceSealedKeys(
              selfdevice.device.id, dev.sealedUserKeysForDevices());
      CHECK_EQ(
          encUserKey.value(),
          SealedEncryptionKeyPair{dev.publicEncryptionKey(), *encryptedKey});
    }
  }

  SUBCASE("processing server entries for the user")
  {
    auto const [user, sealedKeys] = Updater::processUserSealedKeys(
        selfdevice.device.keys,
        builder.trustchainContext(),
        gsl::make_span(builder.entries())
            .as_span<Tanker::Trustchain::ServerEntry const>()
            .subspan(1));
    CHECK_EQ(sealedKeys.size(), 5);

    SUBCASE("recovering keys")
    {
      auto const userKeys = Updater::recoverUserKeys(
          selfdevice.device.keys.encryptionKeyPair, sealedKeys);
      CHECK_EQ(userKeys.size(), 5);
      auto const alice = builder.findUser("Alice");
      CHECK_EQ(userKeys.back(), alice.value().userKeys.back().keyPair);
    }
  }
}
