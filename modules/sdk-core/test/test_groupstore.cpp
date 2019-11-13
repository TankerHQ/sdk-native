#include <Tanker/Groups/GroupStore.hpp>

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

  GroupStore groupStore(dbPtr.get());

  auto const group = InternalGroup{
      make<GroupId>("group id"),
      Crypto::makeSignatureKeyPair(),
      Crypto::makeEncryptionKeyPair(),
      make<Crypto::Hash>("last block hash"),
      1234,
  };
  auto const externalGroup = ExternalGroup{
      make<GroupId>("group id"),
      group.signatureKeyPair.publicKey,
      nonstd::nullopt,
      group.encryptionKeyPair.publicKey,
      make<Crypto::Hash>("last block hash"),
      1234,
  };
  auto const groupProvisionalUser = GroupProvisionalUser{
      make<Crypto::PublicSignatureKey>("app public signature key"),
      make<Crypto::PublicSignatureKey>("tanker public signature key"),
      make<Crypto::TwoTimesSealedPrivateEncryptionKey>(
          "encrypted private encryption key"),
  };
  auto externalGroupWithKey = externalGroup;
  externalGroupWithKey.encryptedPrivateSignatureKey =
      make<Crypto::SealedPrivateSignatureKey>("encrypted private key");

  SUBCASE("it should not find a non-existent group")
  {
    auto const unexistentGroupId = make<GroupId>("unexistent");
    auto const unexistentGroupKey =
        make<Crypto::PublicEncryptionKey>("unexistent");

    CHECK_EQ(AWAIT(groupStore.findInternalById(unexistentGroupId)),
             nonstd::nullopt);
    CHECK_EQ(
        AWAIT(groupStore.findInternalByPublicEncryptionKey(unexistentGroupKey)),
        nonstd::nullopt);
    CHECK_EQ(AWAIT(groupStore.findExternalById(unexistentGroupId)),
             nonstd::nullopt);
    CHECK_EQ(
        AWAIT(groupStore.findExternalByPublicEncryptionKey(unexistentGroupKey)),
        nonstd::nullopt);
  }

  SUBCASE("it should find a group that was inserted")
  {
    AWAIT_VOID(groupStore.put(group));
    CHECK_EQ(AWAIT(groupStore.findInternalById(group.id)).value(), group);
    CHECK_EQ(AWAIT(groupStore.findExternalById(group.id)).value(),
             externalGroup);
    CHECK_EQ(AWAIT(groupStore.findInternalByPublicEncryptionKey(
                       group.encryptionKeyPair.publicKey))
                 .value(),
             group);
    CHECK_EQ(AWAIT(groupStore.findExternalByPublicEncryptionKey(
                       group.encryptionKeyPair.publicKey))
                 .value(),
             externalGroup);
  }

  SUBCASE("it should find an external group that was inserted")
  {
    AWAIT_VOID(groupStore.put(externalGroupWithKey));
    CHECK_EQ(AWAIT(groupStore.findExternalById(group.id)).value(),
             externalGroupWithKey);
    CHECK_EQ(AWAIT(groupStore.findExternalByPublicEncryptionKey(
                 group.encryptionKeyPair.publicKey)),
             externalGroupWithKey);
    CHECK_EQ(AWAIT(groupStore.findInternalById(group.id)), nonstd::nullopt);
    CHECK_EQ(AWAIT(groupStore.findInternalByPublicEncryptionKey(
                 group.encryptionKeyPair.publicKey)),
             nonstd::nullopt);
  }

  SUBCASE("it should overwrite a group that was previously inserted")
  {
    AWAIT_VOID(groupStore.put(group));
    auto group2 = group;
    group2.signatureKeyPair = Crypto::makeSignatureKeyPair();
    group2.encryptionKeyPair = Crypto::makeEncryptionKeyPair();
    group2.lastBlockHash = make<Crypto::Hash>("other last");
    group2.lastBlockIndex = 9999;
    AWAIT_VOID(groupStore.put(group2));
    CHECK_EQ(AWAIT(groupStore.findInternalById(group2.id)).value(), group2);
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
    group2.lastBlockIndex = 9999;
    AWAIT_VOID(groupStore.put(group2));
    CHECK_EQ(AWAIT(groupStore.findInternalById(group2.id)).value(), group2);
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
    externalGroup2.lastBlockIndex = 9999;
    AWAIT_VOID(groupStore.put(externalGroup2));
    CHECK_EQ(AWAIT(groupStore.findExternalById(externalGroup2.id)).value(),
             externalGroup2);
    CHECK_EQ(AWAIT(groupStore.findInternalById(externalGroup2.id)),
             nonstd::nullopt);
  }

  SUBCASE("it should find an external group with one of its provisional users")
  {
    auto externalGroup2(externalGroupWithKey);
    externalGroup2.provisionalUsers = {groupProvisionalUser};
    AWAIT_VOID(groupStore.put(externalGroup2));
    auto const groups = AWAIT(groupStore.findExternalGroupsByProvisionalUser(
        groupProvisionalUser.appPublicSignatureKey(),
        groupProvisionalUser.tankerPublicSignatureKey()));
    REQUIRE(groups.size() == 1);
    CHECK_EQ(groups[0], externalGroup2);
  }
}
