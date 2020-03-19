#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Revocation.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Users/Updater.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <Tanker/Verif/Helpers.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Entries.hpp>

#include <gsl-lite.hpp>

#include <doctest.h>

#include "TrustchainGenerator.hpp"

namespace Updater = Tanker::Users::Updater;
namespace Actions = Tanker::Trustchain::Actions;

using Tanker::Crypto::SealedEncryptionKeyPair;

namespace
{
auto revokeADeviceGetAnEntry(
    std::vector<Tanker::Trustchain::ClientEntry>& entries,
    Tanker::Test::User& user)
{
  auto& target = user.addDevice();
  entries.push_back(target.entry);
  return user.revokeDevice(target);
}

auto makeServerEntry(Tanker::Trustchain::ClientEntry const& clientEntry)
{
  return Tanker::Trustchain::clientToServerEntry(clientEntry);
}

auto makeEntry(Tanker::Trustchain::ClientEntry const& clientEntry)
{
  return Tanker::Verif::makeVerifiedEntry(makeServerEntry(clientEntry));
}
}

TEST_CASE("UserUpdater")
{
  Tanker::Test::Generator generator;
  auto alice = generator.makeUser("Alice");
  auto aliceEntries = alice.entries();
  auto const revokedEntry1 = revokeADeviceGetAnEntry(aliceEntries, alice);
  aliceEntries.push_back(revokedEntry1);
  aliceEntries.push_back(revokeADeviceGetAnEntry(aliceEntries, alice));
  auto const selfdevice = alice.addDevice();
  aliceEntries.push_back(selfdevice.entry);
  auto const revokedEntry2 = revokeADeviceGetAnEntry(aliceEntries, alice);
  aliceEntries.push_back(revokedEntry2);
  aliceEntries.push_back(alice.addDevice().entry);
  aliceEntries.push_back(revokeADeviceGetAnEntry(aliceEntries, alice));

  using Tanker::Verif::makeVerifiedEntry;
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
      auto const encUserKey = Updater::extractEncryptedUserKey(
          *makeEntry(selfdevice.entry)
               .action.get_if<Actions::DeviceCreation>());
      REQUIRE_UNARY(encUserKey.has_value());
      auto const dev = makeServerEntry(selfdevice.entry)
                           .action()
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
          *makeEntry(revokedEntry1).action.get_if<Actions::DeviceRevocation>(),
          selfdevice.id());
      REQUIRE_UNARY(encUserKey.has_value());
      auto const dev = makeServerEntry(revokedEntry1)
                           .action()
                           .get<Actions::DeviceRevocation>()
                           .get<Actions::DeviceRevocation::v2>();
      CHECK_EQ(encUserKey.value(),
               SealedEncryptionKeyPair{dev.previousPublicEncryptionKey(),
                                       dev.sealedKeyForPreviousUserKey()});
    }

    SUBCASE("from a revocation after our device")
    {
      auto const encUserKey = Updater::extractEncryptedUserKey(
          *makeEntry(revokedEntry2).action.get_if<Actions::DeviceRevocation>(),
          selfdevice.id());
      REQUIRE_UNARY(encUserKey.has_value());
      auto const dev = makeServerEntry(revokedEntry2)
                           .action()
                           .get<Actions::DeviceRevocation>()
                           .get<Actions::DeviceRevocation::v2>();

      auto const encryptedKey =
          Tanker::Revocation::findUserKeyFromDeviceSealedKeys(
              selfdevice.id(), dev.sealedUserKeysForDevices());
      CHECK_EQ(
          encUserKey.value(),
          SealedEncryptionKeyPair{dev.publicEncryptionKey(), *encryptedKey});
    }
  }

  SUBCASE("processing server entries for the user")
  {
    auto const [user, sealedKeys] =
        Updater::processUserSealedKeys(selfdevice.keys(),
                                       generator.context(),
                                       generator.makeEntryList(aliceEntries));
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
