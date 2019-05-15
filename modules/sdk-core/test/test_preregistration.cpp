#include <Tanker/Preregistration.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Error.hpp>

#include <Helpers/Await.hpp>

#include <doctest.h>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using namespace Tanker;

TEST_CASE("Preregistration")
{
  auto const db = AWAIT(DataStore::createDatabase(":memory:"));

  TrustchainBuilder builder;
  auto const userResult = builder.makeUser3("alice");
  auto const provisionalUser = builder.makeProvisionalUser("alice@email.com");
  auto picEntry = toVerifiedEntry(builder.claimProvisionalIdentity(
      "alice", provisionalUser.secretProvisionalUser));

  SUBCASE("throws if the user key is not found")
  {
    UserKeyStore userKeyStore(db.get());
    ProvisionalUserKeysStore provisionalUserKeysStore(db.get());
    GroupStore groupStore(db.get());

    CHECK_THROWS_AS(
        AWAIT_VOID(Preregistration::applyEntry(
            userKeyStore, provisionalUserKeysStore, groupStore, picEntry)),
        Error::UserKeyNotFound);
  }

  SUBCASE("can decrypt a preregistration claim")
  {
    auto const userKeyStore =
        builder.makeUserKeyStore(userResult.user, db.get());
    ProvisionalUserKeysStore provisionalUserKeysStore(db.get());
    GroupStore groupStore(db.get());

    CHECK_NOTHROW(AWAIT_VOID(Preregistration::applyEntry(
        *userKeyStore, provisionalUserKeysStore, groupStore, picEntry)));
    auto const gotKeys = AWAIT(provisionalUserKeysStore.findProvisionalUserKeys(
        provisionalUser.secretProvisionalUser.appSignatureKeyPair.publicKey,
        provisionalUser.secretProvisionalUser.tankerSignatureKeyPair
            .publicKey));
    REQUIRE_UNARY(gotKeys);
    CHECK_EQ(gotKeys->appKeys,
             provisionalUser.secretProvisionalUser.appEncryptionKeyPair);
    CHECK_EQ(gotKeys->tankerKeys,
             provisionalUser.secretProvisionalUser.tankerEncryptionKeyPair);
  }

  SUBCASE("can decrypt a group key with a claim")
  {
    auto const group =
        builder.makeGroup(userResult.user.devices[0],
                          {},
                          {provisionalUser.publicProvisionalUser});

    auto const userKeyStore =
        builder.makeUserKeyStore(userResult.user, db.get());
    ProvisionalUserKeysStore provisionalUserKeysStore(db.get());
    auto const groupStore =
        builder.makeGroupStore({group.group.tankerGroup.id}, db.get());

    CHECK_NOTHROW(AWAIT_VOID(Preregistration::applyEntry(
        *userKeyStore, provisionalUserKeysStore, *groupStore, picEntry)));

    CHECK_EQ(
        AWAIT(groupStore->findFullById(group.group.tankerGroup.id)).value(),
        group.group.tankerGroup);
  }
}
