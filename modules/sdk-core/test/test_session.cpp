#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Session.hpp>

#include <doctest.h>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "MockConnection.hpp"
#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using namespace Tanker;

namespace
{
std::unique_ptr<Client> makeClient()
{
  auto connection = std::make_unique<MockConnection>();
  ALLOW_CALL(*connection, on("new relevant block", trompeloeil::_));
  return std::make_unique<Client>(std::move(connection));
}
}

TEST_CASE(
    "Session::catchUserKey should put the user key in ContactUserKeyStore")
{
  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice");

  auto const aliceDevice = alice.user.devices.front();
  auto const aliceUserKeyPair = alice.user.userKeys.back();

  auto db = AWAIT(DataStore::createDatabase(":memory:"));
  auto dbPtr = db.get();
  auto deviceKeyStore = AWAIT(DeviceKeyStore::open(db.get(), aliceDevice.keys));
  auto client = makeClient();

  Session session({std::move(db),
                   builder.trustchainId(),
                   alice.user.userId,
                   Crypto::SymmetricKey{},
                   std::move(deviceKeyStore),
                   std::move(client)});

  auto const entry = toVerifiedEntry(alice.entry);
  auto const deviceCreation =
      mpark::get<Trustchain::Actions::DeviceCreation>(entry.action.variant());

  AWAIT_VOID(
      session.catchUserKey(Trustchain::DeviceId{entry.hash}, deviceCreation));

  CHECK_EQ(AWAIT(dbPtr->findContactUserKey(alice.user.userId)).value(),
           aliceUserKeyPair.keyPair.publicKey);
}
