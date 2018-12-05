#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/ContactUserKeys.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Session.hpp>

#include <doctest.h>
#include <sqlpp11/sqlpp11.h>

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

Crypto::PublicEncryptionKey userKeyFromDb(
    sqlpp::sqlite3::connection* connection, UserId const& id)
{
  Tanker::DbModels::contact_user_keys::contact_user_keys tab{};

  auto rows = (*connection)(select(tab.public_encryption_key)
                                .from(tab)
                                .where(tab.user_id == id.base()));
  return DataStore::extractBlob<Crypto::PublicEncryptionKey>(
      rows.front().public_encryption_key);
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
  auto connection = db.get()->getConnection();
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
      mpark::get<DeviceCreation>(entry.action.variant());

  AWAIT_VOID(session.catchUserKey(DeviceId{entry.hash}, deviceCreation));

  CHECK_EQ(userKeyFromDb(connection, alice.user.userId),
           aliceUserKeyPair.keyPair.publicKey);
}
