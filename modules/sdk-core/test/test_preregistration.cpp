#include <Tanker/ProvisionalUsers/Updater.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

using namespace Tanker;
using namespace Tanker::Errors;

TEST_CASE("ProvisionalUsers")
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

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT_VOID(ProvisionalUsers::Updater::extractKeysToStore(userKeyStore,
                                                                 picEntry)),
        Errc::InternalError);
  }

  SUBCASE("can decrypt a preregistration claim")
  {
    auto const userKeyStore =
        builder.makeUserKeyStore(userResult.user, db.get());
    ProvisionalUserKeysStore provisionalUserKeysStore(db.get());

    auto const gotKeys = AWAIT(
        ProvisionalUsers::Updater::extractKeysToStore(*userKeyStore, picEntry));
    CHECK_EQ(
        gotKeys.appSignaturePublicKey,
        provisionalUser.secretProvisionalUser.appSignatureKeyPair.publicKey);
    CHECK_EQ(
        gotKeys.tankerSignaturePublicKey,
        provisionalUser.secretProvisionalUser.tankerSignatureKeyPair.publicKey);
    CHECK_EQ(gotKeys.appEncryptionKeyPair,
             provisionalUser.secretProvisionalUser.appEncryptionKeyPair);
    CHECK_EQ(gotKeys.tankerEncryptionKeyPair,
             provisionalUser.secretProvisionalUser.tankerEncryptionKeyPair);
  }
}
