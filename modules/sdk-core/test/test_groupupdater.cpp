#include <Tanker/Groups/Updater.hpp>

#include <Tanker/Crypto/Crypto.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "LocalUserAccessorMock.hpp"
#include "ProvisionalUsersAccessorMock.hpp"

#include "TrustchainGenerator.hpp"

#include <boost/variant2/variant.hpp>

#include <catch2/catch.hpp>

using namespace Tanker;

namespace
{
auto makeEntries = [](auto const& item) { return item.entries(); };

template <typename R>
void GroupMatcher(Group const& resultGroup, Test::Group const& testGroup)
{
  auto const group = boost::variant2::get_if<R>(&resultGroup);
  REQUIRE(group);
  CHECK(group->lastBlockHash == testGroup.lastBlockHash());
  CHECK(group->lastKeyRotationBlockHash ==
        testGroup.lastKeyRotationBlockHash());
  CHECK(group->id == testGroup.id());
  if constexpr (std::is_same_v<R, InternalGroup>)
  {
    CHECK(group->encryptionKeyPair == testGroup.currentEncKp());
    CHECK(group->signatureKeyPair == testGroup.currentSigKp());
  }
  else if constexpr (std::is_same_v<R, ExternalGroup>)
  {
    CHECK(group->publicEncryptionKey == testGroup.currentEncKp().publicKey);
    CHECK(group->publicSignatureKey == testGroup.currentSigKp().publicKey);
    auto const decrypted = Crypto::sealDecrypt(
        group->encryptedPrivateSignatureKey, testGroup.currentEncKp());
    CHECK(decrypted == testGroup.currentSigKp().privateKey);
  }
  else
    static_assert(sizeof(R) && false, "please add the new group type");
}
}

TEST_CASE("Group V1")
{
  Test::Generator generator;
  auto const alice = generator.makeUser("alice");
  auto const bob = generator.makeUser("bob");
  auto aliceLocalUserAccessor = LocalUserAccessorMock{};
  auto aliceProvisionalUsersAccessor = ProvisionalUsersAccessorMock{};

  auto aliceLocalUser = static_cast<Users::LocalUser>(alice);

  REQUIRE_CALL(aliceLocalUserAccessor, get())
      .LR_RETURN(aliceLocalUser)
      .TIMES(AT_LEAST(0));

  SECTION("GroupCreation")
  {
    SECTION("handles creation of a group I am part of")
    {
      auto const testGroup =
          generator.makeGroupV1(alice.devices().front(), {alice});
      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(testGroup).front()));

      GroupMatcher<InternalGroup>(resultGroup, testGroup);
    }

    SECTION("handles creation of a group I am *not* part of")
    {
      auto const group = generator.makeGroupV1(bob.devices().front(), {bob});
      REQUIRE_CALL(aliceLocalUserAccessor, pull())
          .LR_RETURN(makeCoTask<Users::LocalUser const&>(aliceLocalUser));
      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(group).front()));

      GroupMatcher<ExternalGroup>(resultGroup, group);
    }
  }
  SECTION("GroupAddition")
  {
    SECTION("Alice sees Bob being added to her group")
    {
      auto aliceGroup = generator.makeGroupV1(alice.devices()[0], {alice});
      aliceGroup.addUsersV1(alice.devices()[0], {bob});
      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupAddition(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               aliceGroup,
                                               makeEntries(aliceGroup).back()));
      GroupMatcher<InternalGroup>(resultGroup, aliceGroup);
    }

    SECTION("Alice sees herself being added to Bob's group")
    {
      auto const bobGroup = generator.makeGroupV1(bob.devices()[0], {bob});
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsersV1(bob.devices()[0], {alice});
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          makeEntries(bobGroupUpdated).back()));
      GroupMatcher<InternalGroup>(resultGroup, bobGroupUpdated);
    }

    SECTION("Alice sees Charlie being added to Bob's group")
    {
      auto bobGroup = generator.makeGroupV1(bob.devices()[0], {bob});
      auto const charlie = generator.makeUser("charlie");
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsersV1(bob.devices()[0], {charlie});
      REQUIRE_CALL(aliceLocalUserAccessor, pull())
          .LR_RETURN(makeCoTask<Users::LocalUser const&>(aliceLocalUser));
      // Storing it into a local variable is required to workaround a VS2019 ICE
      auto const entry = makeEntries(bobGroupUpdated).back();
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          entry));
      GroupMatcher<ExternalGroup>(resultGroup, bobGroupUpdated);
    }
  }
}

TEST_CASE("Group V2")
{
  Test::Generator generator;
  auto const alice = generator.makeUser("alice");
  auto aliceLocalUserAccessor = LocalUserAccessorMock{};
  auto aliceProvisionalUsersAccessor = ProvisionalUsersAccessorMock{};
  auto const aliceProvisionalUser =
      generator.makeProvisionalUser("alice@tanker");
  auto const bob = generator.makeUser("bob");

  auto const aliceLocalUser = static_cast<Users::LocalUser>(alice);

  REQUIRE_CALL(aliceLocalUserAccessor, get())
      .LR_RETURN(aliceLocalUser)
      .TIMES(AT_LEAST(0));

  SECTION("GroupCreation")
  {

    SECTION("handles creation of a group I am part of")
    {
      auto const group =
          generator.makeGroupV2(alice.devices().front(), {alice});
      REQUIRE_CALL(aliceLocalUserAccessor,
                   pullUserKeyPair(alice.userKeys().back().publicKey))
          .LR_RETURN(makeCoTask(std::make_optional(alice.userKeys().back())));

      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(group).front()));

      GroupMatcher<InternalGroup>(resultGroup, group);
    }

    SECTION("handles creation of a group I am *not* part of")
    {
      auto const bobGroup = generator.makeGroupV2(bob.devices().front(), {bob});

      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(bobGroup).front()));

      GroupMatcher<ExternalGroup>(resultGroup, bobGroup);
    }

    SECTION(
        "handles creation of a group I am part of through a provisional "
        "identity")
    {
      auto const bobGroup = generator.makeGroupV2(
          bob.devices().front(), {bob}, {aliceProvisionalUser});
      REQUIRE_CALL(aliceProvisionalUsersAccessor,
                   findEncryptionKeysFromCache(trompeloeil::_, trompeloeil::_))
          .RETURN(makeCoTask(
              std::make_optional<ProvisionalUserKeys>(aliceProvisionalUser)));

      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(bobGroup).front()));

      GroupMatcher<InternalGroup>(resultGroup, bobGroup);
    }
  }

  SECTION("GroupAddition")
  {
    REQUIRE_CALL(aliceLocalUserAccessor, get())
        .LR_RETURN(aliceLocalUser)
        .TIMES(AT_LEAST(0));

    SECTION("Alice sees Bob being added to her group")
    {
      auto aliceGroup = generator.makeGroupV2(alice.devices().front(), {alice});
      aliceGroup.addUsersV2(alice.devices()[0], {bob});
      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupAddition(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               aliceGroup,
                                               makeEntries(aliceGroup).back()));
      GroupMatcher<InternalGroup>(resultGroup, aliceGroup);
    }

    SECTION("Alice sees herself being added to Bob's group")
    {
      auto const bobGroup = generator.makeGroupV2(bob.devices()[0], {bob});
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsersV2(bob.devices()[0], {alice});
      REQUIRE_CALL(aliceLocalUserAccessor,
                   pullUserKeyPair(alice.userKeys().back().publicKey))
          .LR_RETURN(makeCoTask(std::make_optional(alice.userKeys().back())));
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          makeEntries(bobGroupUpdated).back()));
      GroupMatcher<InternalGroup>(resultGroup, bobGroupUpdated);
    }

    SECTION("Alice sees Charlie being added to Bob's group")
    {
      auto bobGroup = generator.makeGroupV2(bob.devices()[0], {bob});
      auto const charlie = generator.makeUser("charlie");
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsersV2(bob.devices()[0], {charlie});
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          makeEntries(bobGroupUpdated).back()));
      GroupMatcher<ExternalGroup>(resultGroup, bobGroupUpdated);
    }

    SECTION(
        "Alice sees herself being added to Bob's group as a provisional user")
    {
      auto bobGroup = generator.makeGroupV2(bob.devices()[0], {bob}, {});
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsersV2(bob.devices()[0], {}, {aliceProvisionalUser});
      REQUIRE_CALL(aliceProvisionalUsersAccessor,
                   findEncryptionKeysFromCache(trompeloeil::_, trompeloeil::_))
          .RETURN(makeCoTask(
              std::make_optional<ProvisionalUserKeys>(aliceProvisionalUser)));
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          makeEntries(bobGroupUpdated).back()));

      GroupMatcher<InternalGroup>(resultGroup, bobGroupUpdated);
    }
  }
}

TEST_CASE("Group V3")
{
  Test::Generator generator;
  auto const alice = generator.makeUser("alice");
  auto aliceLocalUserAccessor = LocalUserAccessorMock{};
  auto aliceProvisionalUsersAccessor = ProvisionalUsersAccessorMock{};
  auto const aliceProvisionalUser =
      generator.makeProvisionalUser("alice@tanker");
  auto const bob = generator.makeUser("bob");

  auto const aliceLocalUser = static_cast<Users::LocalUser>(alice);

  REQUIRE_CALL(aliceLocalUserAccessor, get())
      .LR_RETURN(aliceLocalUser)
      .TIMES(AT_LEAST(0));

  SECTION("GroupCreation")
  {
    SECTION("handles creation of a group I am part of")
    {
      REQUIRE_CALL(aliceLocalUserAccessor,
                   pullUserKeyPair(alice.userKeys().back().publicKey))
          .LR_RETURN(makeCoTask(std::make_optional(alice.userKeys().back())));
      auto const group = alice.makeGroup();

      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(group).front()));

      GroupMatcher<InternalGroup>(resultGroup, group);
    }

    SECTION("handles creation of a group I am *not* part of")
    {
      auto const bobGroup = bob.makeGroup();

      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(bobGroup).front()));

      GroupMatcher<ExternalGroup>(resultGroup, bobGroup);
    }

    SECTION(
        "handles creation of a group I am part of through a provisional "
        "identity")
    {
      auto const bobGroup = bob.makeGroup({}, {aliceProvisionalUser});
      REQUIRE_CALL(aliceProvisionalUsersAccessor,
                   findEncryptionKeysFromCache(trompeloeil::_, trompeloeil::_))
          .RETURN(makeCoTask(
              std::make_optional<ProvisionalUserKeys>(aliceProvisionalUser)));

      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupCreation(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               makeEntries(bobGroup).front()));

      GroupMatcher<InternalGroup>(resultGroup, bobGroup);
    }
  }

  SECTION("GroupAddition")
  {
    SECTION("Alice sees Bob being added to her group")
    {
      auto aliceGroup = generator.makeGroup(alice.devices()[0], {alice});
      aliceGroup.addUsers(alice.devices()[0], {bob});
      auto const resultGroup = AWAIT(
          GroupUpdater::applyUserGroupAddition(aliceLocalUserAccessor,
                                               aliceProvisionalUsersAccessor,
                                               aliceGroup,
                                               makeEntries(aliceGroup).back()));
      GroupMatcher<InternalGroup>(resultGroup, aliceGroup);
    }

    SECTION("Alice sees herself being added to Bob's group")
    {
      auto const bobGroup = generator.makeGroup(bob.devices()[0], {bob});
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsers(bob.devices()[0], {alice});
      REQUIRE_CALL(aliceLocalUserAccessor,
                   pullUserKeyPair(alice.userKeys().back().publicKey))
          .LR_RETURN(makeCoTask(std::make_optional(alice.userKeys().back())));
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          makeEntries(bobGroupUpdated).back()));
      GroupMatcher<InternalGroup>(resultGroup, bobGroupUpdated);
    }

    SECTION("Alice sees Charlie being added to Bob's group")
    {
      auto bobGroup = generator.makeGroup(bob.devices()[0], {bob});
      auto const charlie = generator.makeUser("charlie");
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsers(bob.devices()[0], {charlie});
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          makeEntries(bobGroupUpdated).back()));
      GroupMatcher<ExternalGroup>(resultGroup, bobGroupUpdated);
    }

    SECTION(
        "Alice sees herself being added to Bob's group as a provisional user")
    {
      auto bobGroup = generator.makeGroup(bob.devices()[0], {bob}, {});
      auto bobGroupUpdated = bobGroup;
      bobGroupUpdated.addUsers(bob.devices()[0], {}, {aliceProvisionalUser});
      REQUIRE_CALL(aliceProvisionalUsersAccessor,
                   findEncryptionKeysFromCache(trompeloeil::_, trompeloeil::_))
          .RETURN(makeCoTask(
              std::make_optional<ProvisionalUserKeys>(aliceProvisionalUser)));
      auto const resultGroup = AWAIT(GroupUpdater::applyUserGroupAddition(
          aliceLocalUserAccessor,
          aliceProvisionalUsersAccessor,
          static_cast<ExternalGroup>(bobGroup),
          makeEntries(bobGroupUpdated).back()));

      GroupMatcher<InternalGroup>(resultGroup, bobGroupUpdated);
    }
  }
}
