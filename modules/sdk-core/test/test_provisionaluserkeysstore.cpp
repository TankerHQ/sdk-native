#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;

TEST_CASE("ProvisionalUserKeysStore")
{
  auto db = DataStore::SqliteBackend().open(DataStore::MemoryPath, DataStore::MemoryPath);

  SECTION("it should create and destroy a ProvisionalUserKeysStore")
  {
    ProvisionalUserKeysStore store({}, db.get());
  }

  SECTION("it should not find a non-existent provisional user")
  {
    auto const unexistentPubKey = make<Crypto::PublicSignatureKey>("unexistent");

    ProvisionalUserKeysStore store({}, db.get());
    CHECK(!AWAIT(store.findProvisionalUserKeys(unexistentPubKey, unexistentPubKey)));
  }

  SECTION("it should find a key that was inserted")
  {
    auto const appPubKey = make<Crypto::PublicSignatureKey>("app pub key...");
    auto const tankerPubKey = make<Crypto::PublicSignatureKey>("tanker pub key...");
    auto const kp1 = Tanker::Crypto::makeEncryptionKeyPair();
    auto const kp2 = Tanker::Crypto::makeEncryptionKeyPair();

    ProvisionalUserKeysStore store({}, db.get());

    AWAIT_VOID(store.putProvisionalUserKeys(appPubKey, tankerPubKey, {kp1, kp2}));
    auto const gotKeyPair = AWAIT(store.findProvisionalUserKeys(appPubKey, tankerPubKey));

    REQUIRE(gotKeyPair.has_value());
    CHECK(kp1 == gotKeyPair->appKeys);
    CHECK(kp2 == gotKeyPair->tankerKeys);
  }

  SECTION("it should not find a key with either signature keys are false")
  {
    auto const unexistentPubKey = make<Crypto::PublicSignatureKey>("unexistent");
    auto const appPubKey = make<Crypto::PublicSignatureKey>("app pub key...");
    auto const tankerPubKey = make<Crypto::PublicSignatureKey>("tanker pub key...");
    auto const kp1 = Tanker::Crypto::makeEncryptionKeyPair();
    auto const kp2 = Tanker::Crypto::makeEncryptionKeyPair();

    ProvisionalUserKeysStore store({}, db.get());

    AWAIT_VOID(store.putProvisionalUserKeys(appPubKey, tankerPubKey, {kp1, kp2}));
    auto const gotKeyPair = AWAIT(store.findProvisionalUserKeys(unexistentPubKey, tankerPubKey));

    REQUIRE(!gotKeyPair.has_value());

    auto const gotKeyPair2 = AWAIT(store.findProvisionalUserKeys(appPubKey, unexistentPubKey));

    REQUIRE(!gotKeyPair2.has_value());
  }

  SECTION("it should find a key by app public encryption key")
  {
    auto const appPubKey = make<Crypto::PublicSignatureKey>("app pub key...");
    auto const tankerPubKey = make<Crypto::PublicSignatureKey>("tanker pub key...");
    auto const appKeys = Tanker::Crypto::makeEncryptionKeyPair();
    auto const tankerKeys = Tanker::Crypto::makeEncryptionKeyPair();

    ProvisionalUserKeysStore store({}, db.get());

    AWAIT_VOID(store.putProvisionalUserKeys(appPubKey, tankerPubKey, {appKeys, tankerKeys}));
    auto const gotKeyPair = AWAIT(store.findProvisionalUserKeysByAppPublicSignatureKey(appPubKey));

    REQUIRE(gotKeyPair.has_value());
    CHECK(appKeys == gotKeyPair->appKeys);
    CHECK(tankerKeys == gotKeyPair->tankerKeys);
  }
}
