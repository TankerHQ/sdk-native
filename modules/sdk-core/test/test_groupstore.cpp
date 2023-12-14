#include <Tanker/Groups/Store.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;
using Tanker::Trustchain::GroupId;

namespace Tanker
{
// Do not let doctest pickup variant2's operator<<
inline std::ostream& operator<<(std::ostream& os, Group const&) = delete;
}

TEST_CASE("GroupStore")
{
  auto db = DataStore::SqliteBackend().open(DataStore::MemoryPath, DataStore::MemoryPath);

  Groups::Store groupStore({}, db.get());

  auto const group = InternalGroup{
      make<GroupId>("group id"),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeEncryptionKeyPair(),
      make<Crypto::Hash>("last block hash"),
      make<Crypto::Hash>("last key rotation block hash"),
  };
  auto const externalGroup = ExternalGroup{
      make<GroupId>("group id"),
      group.signatureKeyPair.publicKey,
      make<Crypto::SealedPrivateSignatureKey>("encrypted private key"),
      group.encryptionKeyPair.publicKey,
      make<Crypto::Hash>("last block hash"),
      make<Crypto::Hash>("last key rotation block hash"),
  };
  SECTION("it should not find a non-existent group")
  {
    auto const unexistentGroupId = make<GroupId>("unexistent");
    auto const unexistentGroupKey = make<Crypto::PublicEncryptionKey>("unexistent");

    CHECK(AWAIT(groupStore.findInternalByPublicEncryptionKey(unexistentGroupKey)) == std::nullopt);
    CHECK(AWAIT(groupStore.findById(unexistentGroupId)) == std::nullopt);
    CHECK(AWAIT(groupStore.findByPublicEncryptionKey(unexistentGroupKey)) == std::nullopt);
  }

  SECTION("it should find a group that was inserted")
  {
    AWAIT_VOID(groupStore.put(group));
    CHECK(AWAIT(groupStore.findById(group.id)).value() == Group{group});
    CHECK(AWAIT(groupStore.findInternalByPublicEncryptionKey(group.encryptionKeyPair.publicKey)).value() == group);
    CHECK(AWAIT(groupStore.findByPublicEncryptionKey(group.encryptionKeyPair.publicKey)).value() == Group{group});
  }

  SECTION("it should find an external group that was inserted")
  {
    AWAIT_VOID(groupStore.put(externalGroup));
    CHECK(AWAIT(groupStore.findById(group.id)).value() == Group{externalGroup});
    CHECK(AWAIT(groupStore.findByPublicEncryptionKey(group.encryptionKeyPair.publicKey)) == Group{externalGroup});
    CHECK(AWAIT(groupStore.findInternalByPublicEncryptionKey(group.encryptionKeyPair.publicKey)) == std::nullopt);
  }

  SECTION("it should overwrite a group that was previously inserted")
  {
    AWAIT_VOID(groupStore.put(group));
    auto group2 = group;
    group2.signatureKeyPair = Crypto::makeSignatureKeyPair();
    group2.encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    group2.lastBlockHash = make<Crypto::Hash>("other last");
    group2.lastKeyRotationBlockHash = make<Crypto::Hash>("and another one");
    AWAIT_VOID(groupStore.put(group2));
    CHECK(AWAIT(groupStore.findById(group2.id)).value() == Group{group2});
  }

  SECTION(
      "it should overwrite an external group with a fullgroup (we got added to "
      "a group)")
  {
    AWAIT_VOID(groupStore.put(externalGroup));
    auto group2 = group;
    group2.signatureKeyPair = Crypto::makeSignatureKeyPair();
    group2.encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    group2.lastBlockHash = make<Crypto::Hash>("other last");
    group2.lastKeyRotationBlockHash = make<Crypto::Hash>("and another one");
    AWAIT_VOID(groupStore.put(group2));
    CHECK(AWAIT(groupStore.findById(group2.id)).value() == Group{group2});
  }

  SECTION(
      "it should overwrite a full group with an external group (we got removed "
      "from the group)")
  {
    AWAIT_VOID(groupStore.put(group));
    auto externalGroup2 = externalGroup;
    externalGroup2.publicSignatureKey = Crypto::makeSignatureKeyPair().publicKey;
    externalGroup2.publicEncryptionKey = Crypto::makeEncryptionKeyPair().publicKey;
    externalGroup2.lastBlockHash = make<Crypto::Hash>("other last");
    externalGroup2.lastKeyRotationBlockHash = make<Crypto::Hash>("and another one");
    AWAIT_VOID(groupStore.put(externalGroup2));
    CHECK(AWAIT(groupStore.findById(externalGroup2.id)).value() == Group{externalGroup2});
  }
}
