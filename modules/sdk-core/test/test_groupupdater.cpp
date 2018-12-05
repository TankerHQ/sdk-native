#include <Tanker/Groups/GroupUpdater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/Groups/GroupStore.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

#include <doctest.h>

using namespace Tanker;

TEST_CASE("GroupUpdater UserGroupCreation")
{
  auto const aliceDb = AWAIT(DataStore::createDatabase(":memory:"));
  GroupStore groupStore(aliceDb.get());

  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice");
  auto const aliceKeyStore =
      builder.makeUserKeyStore(alice.user, aliceDb.get());

  SUBCASE("handles creation of a group I am part of")
  {
    auto const group = builder.makeGroup(alice.user.devices[0], {alice.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        groupStore, *aliceKeyStore, toVerifiedEntry(group.entry)));
    CHECK_EQ(AWAIT(groupStore.findFullById(group.group.tankerGroup.id)).value(),
             group.group.tankerGroup);
  }

  SUBCASE("handles creation of a group I am *not* part of")
  {
    auto const bob = builder.makeUser3("bob");

    auto const group = builder.makeGroup(bob.user.devices[0], {bob.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        groupStore, *aliceKeyStore, toVerifiedEntry(group.entry)));

    CHECK_EQ(
        AWAIT(groupStore.findExternalById(group.group.tankerGroup.id)).value(),
        group.group.asExternalGroup());
  }
}

TEST_CASE("GroupUpdater UserGroupAddition")
{
  auto const aliceDb = AWAIT(DataStore::createDatabase(":memory:"));
  GroupStore aliceGroupStore(aliceDb.get());

  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice");
  auto const bob = builder.makeUser3("bob");
  auto const aliceKeyStore =
      builder.makeUserKeyStore(alice.user, aliceDb.get());

  SUBCASE("Alice sees Bob being added to her group")
  {
    auto const aliceGroup =
        builder.makeGroup(alice.user.devices[0], {alice.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        aliceGroupStore, *aliceKeyStore, toVerifiedEntry(aliceGroup.entry)));

    auto const updatedGroup = builder.addUserToGroup(
        alice.user.devices[0], aliceGroup.group, {bob.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        aliceGroupStore, *aliceKeyStore, toVerifiedEntry(updatedGroup.entry)));
    CHECK_EQ(
        AWAIT(aliceGroupStore.findFullById(aliceGroup.group.tankerGroup.id))
            .value(),
        updatedGroup.group.tankerGroup);
  }

  SUBCASE("Alice sees herself being added to Bob's group")
  {
    auto const bobGroup = builder.makeGroup(bob.user.devices[0], {bob.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        aliceGroupStore, *aliceKeyStore, toVerifiedEntry(bobGroup.entry)));

    auto const updatedGroup = builder.addUserToGroup(
        bob.user.devices[0], bobGroup.group, {alice.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        aliceGroupStore, *aliceKeyStore, toVerifiedEntry(updatedGroup.entry)));
    CHECK_EQ(AWAIT(aliceGroupStore.findFullById(bobGroup.group.tankerGroup.id))
                 .value(),
             updatedGroup.group.tankerGroup);
  }

  SUBCASE("Alice sees Charly being added to Bob's group")
  {
    auto const bobGroup = builder.makeGroup(bob.user.devices[0], {bob.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        aliceGroupStore, *aliceKeyStore, toVerifiedEntry(bobGroup.entry)));

    auto const charly = builder.makeUser3("charly");

    auto const updatedGroup = builder.addUserToGroup(
        bob.user.devices[0], bobGroup.group, {charly.user});
    AWAIT_VOID(GroupUpdater::applyEntry(
        aliceGroupStore, *aliceKeyStore, toVerifiedEntry(updatedGroup.entry)));

    CHECK_EQ(
        AWAIT(aliceGroupStore.findExternalById(bobGroup.group.tankerGroup.id))
            .value(),
        updatedGroup.group.asExternalGroup());
  }
}
