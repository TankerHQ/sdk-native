#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Session.hpp>

#include <doctest.h>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "MockConnection.hpp"
#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;
using namespace type_literals;

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

  auto const aliceUserKeyPair = alice.user.userKeys.back();

  auto db = AWAIT(DataStore::createDatabase(":memory:"));
  auto dbPtr = db.get();
  auto localUser = AWAIT(Users::LocalUser::open(
      Identity::createIdentity(
          alice.entry.trustchainId(),
          make<Crypto::PrivateSignatureKey>("a private signature key"),
          alice.user.userId),
      db.get()));
  auto client = makeClient();

  Session session({std::move(db),
                   builder.trustchainId(),
                   std::move(localUser),
                   std::move(client)});

  auto const entry = toVerifiedEntry(alice.entry);
  auto const deviceCreation = entry.action.get<DeviceCreation>();

  AWAIT_VOID(
      session.catchUserKey(Trustchain::DeviceId{entry.hash}, deviceCreation));

  CHECK_EQ(AWAIT(dbPtr->findContactUserKey(alice.user.userId)).value(),
           aliceUserKeyPair.keyPair.publicKey);
}
