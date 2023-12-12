#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Users/Updater.hpp>

#include <Tanker/Crypto/Format/Format.hpp>

#include <Tanker/Verif/Helpers.hpp>

#include <Helpers/Await.hpp>

#include <gsl/gsl-lite.hpp>

#include <range/v3/range/conversion.hpp>

#include <catch2/catch_test_macros.hpp>

#include "TrustchainGenerator.hpp"

namespace Updater = Tanker::Users::Updater;
namespace Actions = Tanker::Trustchain::Actions;

using namespace Tanker;
using Tanker::Crypto::SealedEncryptionKeyPair;

TEST_CASE("UserUpdater")
{
  Tanker::Test::Generator generator;
  auto alice = generator.makeUser("Alice");
  auto aliceEntries = alice.entries() | ranges::to<std::vector<Trustchain::UserAction>>;
  auto const selfdevice = alice.addDevice();
  aliceEntries.push_back(selfdevice.action);
  aliceEntries.push_back(alice.addDevice().action);

  SECTION("Should find the trustchainID")
  {
    REQUIRE_NOTHROW(Updater::extractTrustchainSignature(generator.context().id(), generator.rootBlock()));
    auto const sig = Updater::extractTrustchainSignature(generator.context().id(), generator.rootBlock());
    CHECK(sig == generator.trustchainSigKp().publicKey);
  }

  SECTION("extract an encrypted user key")
  {
    SECTION("from our device")
    {
      auto const encUserKey = Updater::extractEncryptedUserKey(selfdevice.action);
      REQUIRE(encUserKey.has_value());
      auto const dev = selfdevice.action.get<Actions::DeviceCreation::v3>();
      auto const [publicUserKey, sealedPrivateKey] = *encUserKey;
      CHECK(sealedPrivateKey == dev.sealedPrivateUserEncryptionKey());
      CHECK(encUserKey.value() == SealedEncryptionKeyPair{{}, dev.sealedPrivateUserEncryptionKey()});
    }
  }

  SECTION("processing server entries for the user")
  {
    auto const [user, sealedKeys] =
        Updater::processUserSealedKeys(selfdevice.id(), selfdevice.keys(), generator.context(), aliceEntries);
    CHECK(sealedKeys.size() == 1);

    SECTION("recovering keys")
    {
      auto const userKeys = Updater::recoverUserKeys(selfdevice.keys().encryptionKeyPair, sealedKeys);
      CHECK(userKeys.size() == 1);
      CHECK(userKeys == alice.userKeys());
    }
  }
}
