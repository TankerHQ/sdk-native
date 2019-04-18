#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_CASE("ProvisionalUserKeysStore")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  SUBCASE("it should create and destroy a ProvisionalUserKeysStore")
  {
    ProvisionalUserKeysStore store(dbPtr.get());
  }

  SUBCASE("it should not find a non-existent provisional user")
  {
    auto const unexistentPubKey =
        make<Crypto::PublicSignatureKey>("unexistent");

    ProvisionalUserKeysStore store(dbPtr.get());
    CHECK_UNARY(!AWAIT(
        store.findProvisionalUserKeys(unexistentPubKey, unexistentPubKey)));
  }

  SUBCASE("it should find a key that was inserted")
  {
    auto const appPubKey = make<Crypto::PublicSignatureKey>("app pub key...");
    auto const tankerPubKey =
        make<Crypto::PublicSignatureKey>("tanker pub key...");
    auto const kp1 = Tanker::Crypto::makeEncryptionKeyPair();
    auto const kp2 = Tanker::Crypto::makeEncryptionKeyPair();

    ProvisionalUserKeysStore store(dbPtr.get());

    AWAIT_VOID(
        store.putProvisionalUserKeys(appPubKey, tankerPubKey, {kp1, kp2}));
    auto const gotKeyPair =
        AWAIT(store.findProvisionalUserKeys(appPubKey, tankerPubKey));

    REQUIRE_UNARY(gotKeyPair.has_value());
    CHECK_EQ(kp1, gotKeyPair->appKeys);
    CHECK_EQ(kp2, gotKeyPair->tankerKeys);
  }

  SUBCASE("it should not find a key with either signature keys are false")
  {
    auto const unexistentPubKey =
        make<Crypto::PublicSignatureKey>("unexistent");
    auto const appPubKey = make<Crypto::PublicSignatureKey>("app pub key...");
    auto const tankerPubKey =
        make<Crypto::PublicSignatureKey>("tanker pub key...");
    auto const kp1 = Tanker::Crypto::makeEncryptionKeyPair();
    auto const kp2 = Tanker::Crypto::makeEncryptionKeyPair();

    ProvisionalUserKeysStore store(dbPtr.get());

    AWAIT_VOID(
        store.putProvisionalUserKeys(appPubKey, tankerPubKey, {kp1, kp2}));
    auto const gotKeyPair =
        AWAIT(store.findProvisionalUserKeys(unexistentPubKey, tankerPubKey));

    REQUIRE_UNARY(!gotKeyPair.has_value());

    auto const gotKeyPair2 =
        AWAIT(store.findProvisionalUserKeys(appPubKey, unexistentPubKey));

    REQUIRE_UNARY(!gotKeyPair2.has_value());
  }
}
