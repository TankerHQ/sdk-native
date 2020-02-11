#include <Tanker/Groups/Store.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/ADatabase.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;
using Tanker::Trustchain::GroupId;

TEST_CASE("GroupStore")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  Groups::Store groupStore(dbPtr.get());

  auto const group = InternalGroup{
      make<GroupId>("group id"),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeEncryptionKeyPair(),
      make<Crypto::Hash>("last block hash"),
  };
  auto const externalGroup = ExternalGroup{
      make<GroupId>("group id"),
      group.signatureKeyPair.publicKey,
      std::nullopt,
      group.encryptionKeyPair.publicKey,
      make<Crypto::Hash>("last block hash"),
  };
  auto externalGroupWithKey = externalGroup;
  externalGroupWithKey.encryptedPrivateSignatureKey =
      make<Crypto::SealedPrivateSignatureKey>("encrypted private key");

  SUBCASE("it should not find a non-existent group")
  {
    auto const unexistentGroupId = make<GroupId>("unexistent");
    auto const unexistentGroupKey =
        make<Crypto::PublicEncryptionKey>("unexistent");

    CHECK_EQ(
        AWAIT(groupStore.findInternalByPublicEncryptionKey(unexistentGroupKey)),
        std::nullopt);
    CHECK_EQ(AWAIT(groupStore.findById(unexistentGroupId)), std::nullopt);
    CHECK_EQ(AWAIT(groupStore.findByPublicEncryptionKey(unexistentGroupKey)),
             std::nullopt);
  }

  SUBCASE("it should find a group that was inserted")
  {
    AWAIT_VOID(groupStore.put(group));
    CHECK_EQ(AWAIT(groupStore.findById(group.id)).value(), Group{group});
    CHECK_EQ(AWAIT(groupStore.findInternalByPublicEncryptionKey(
                       group.encryptionKeyPair.publicKey))
                 .value(),
             group);
    CHECK_EQ(AWAIT(groupStore.findByPublicEncryptionKey(
                       group.encryptionKeyPair.publicKey))
                 .value(),
             Group{group});
  }

  SUBCASE("it should find an external group that was inserted")
  {
    AWAIT_VOID(groupStore.put(externalGroupWithKey));
    CHECK_EQ(AWAIT(groupStore.findById(group.id)).value(),
             Group{externalGroupWithKey});
    CHECK_EQ(AWAIT(groupStore.findByPublicEncryptionKey(
                 group.encryptionKeyPair.publicKey)),
             Group{externalGroupWithKey});
    CHECK_EQ(AWAIT(groupStore.findInternalByPublicEncryptionKey(
                 group.encryptionKeyPair.publicKey)),
             std::nullopt);
  }

  SUBCASE("it should overwrite a group that was previously inserted")
  {
    AWAIT_VOID(groupStore.put(group));
    auto group2 = group;
    group2.signatureKeyPair = Crypto::makeSignatureKeyPair();
    group2.encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    group2.lastBlockHash = make<Crypto::Hash>("other last");
    AWAIT_VOID(groupStore.put(group2));
    CHECK_EQ(AWAIT(groupStore.findById(group2.id)).value(), Group{group2});
  }

  SUBCASE(
      "it should overwrite an external group with a fullgroup (we got added to "
      "a group)")
  {
    AWAIT_VOID(groupStore.put(externalGroupWithKey));
    auto group2 = group;
    group2.signatureKeyPair = Crypto::makeSignatureKeyPair();
    group2.encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    group2.lastBlockHash = make<Crypto::Hash>("other last");
    AWAIT_VOID(groupStore.put(group2));
    CHECK_EQ(AWAIT(groupStore.findById(group2.id)).value(), Group{group2});
  }

  SUBCASE(
      "it should overwrite a full group with an external group (we got removed "
      "from the group)")
  {
    AWAIT_VOID(groupStore.put(group));
    auto externalGroup2 = externalGroupWithKey;
    externalGroup2.publicSignatureKey =
        Crypto::makeSignatureKeyPair().publicKey;
    externalGroup2.publicEncryptionKey =
        Crypto::makeEncryptionKeyPair().publicKey;
    externalGroup2.lastBlockHash = make<Crypto::Hash>("other last");
    AWAIT_VOID(groupStore.put(externalGroup2));
    CHECK_EQ(AWAIT(groupStore.findById(externalGroup2.id)).value(),
             Group{externalGroup2});
  }
}
