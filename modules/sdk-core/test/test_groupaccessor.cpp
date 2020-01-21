#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/IRequester.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "FakeProvisionalUsersAccessor.hpp"
#include "TrustchainBuilder.hpp"
#include "UserRequesterStub.hpp"

#include <doctest.h>
#include <trompeloeil.hpp>

using namespace Tanker;
using Tanker::Trustchain::GroupId;

namespace
{
class RequesterStub : public Groups::IRequester
{
public:
  MAKE_MOCK1(getGroupBlocks,
             tc::cotask<std::vector<Trustchain::ServerEntry>>(
                 std::vector<Trustchain::GroupId> const&),
             override);
  MAKE_MOCK1(getGroupBlocks,
             tc::cotask<std::vector<Trustchain::ServerEntry>>(
                 Crypto::PublicEncryptionKey const&),
             override);
};
}

TEST_CASE("GroupAccessor")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));
  Groups::Store groupStore(dbPtr.get());

  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice");
  auto const bob = builder.makeUser3("bob");

  auto const aliceGroup =
      builder.makeGroup(alice.user.devices.front(), {alice.user});
  auto const bobGroup = builder.makeGroup(bob.user.devices.front(), {bob.user});

  RequesterStub requestStub;
  UserRequesterStub userRequestStub;

  auto aliceContactStore =
      builder.makeContactStoreWith({"alice", "bob"}, dbPtr.get());
  Users::UserAccessor aliceUserAccessor(
      builder.trustchainContext(), &userRequestStub, aliceContactStore.get());
  auto const aliceLocalUser = builder.makeLocalUser(alice.user, dbPtr.get());
  auto const aliceProvisionalUserKeysStore =
      builder.makeProvisionalUserKeysStoreWith({}, dbPtr.get());
  auto const aliceProvisionalUsersAccessor =
      std::make_unique<FakeProvisionalUsersAccessor>(
          *aliceProvisionalUserKeysStore);
  Groups::Accessor groupAccessor(&requestStub,
                                 &aliceUserAccessor,
                                 &groupStore,
                                 aliceLocalUser.get(),
                                 aliceProvisionalUsersAccessor.get());

  SUBCASE("it should return cached public encryption keys")
  {
    AWAIT_VOID(groupStore.put(aliceGroup.group.asExternalGroup()));

    auto const result = AWAIT(groupAccessor.getPublicEncryptionKeys(
        {aliceGroup.group.tankerGroup.id}));

    CHECK_EQ(result.found.at(0),
             aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey);
  }

  SUBCASE("it should return cached encryption key pairs")
  {
    AWAIT_VOID(groupStore.put(aliceGroup.group.tankerGroup));

    auto const result = AWAIT(groupAccessor.getEncryptionKeyPair(
        {aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey}));

    CHECK_EQ(result.value(), aliceGroup.group.tankerGroup.encryptionKeyPair);
  }

  SUBCASE("it can request group public keys by invalid groupId")
  {
    auto const unknownGroupId = make<GroupId>("unknownGroup");
    REQUIRE_CALL(requestStub,
                 getGroupBlocks(std::vector<GroupId>{unknownGroupId}))
        .RETURN(makeCoTask(std::vector<Trustchain::ServerEntry>{}));

    auto const result =
        AWAIT(groupAccessor.getPublicEncryptionKeys({unknownGroupId}));

    CHECK(result.found.empty());
    REQUIRE_EQ(result.notFound.size(), 1);
    CHECK_EQ(result.notFound[0], unknownGroupId);
  }

  SUBCASE("it should request group public keys by groupId if not in store")
  {
    REQUIRE_CALL(
        requestStub,
        getGroupBlocks(std::vector<GroupId>{aliceGroup.group.tankerGroup.id}))
        .RETURN(
            makeCoTask(std::vector<Trustchain::ServerEntry>{aliceGroup.entry}));
    REQUIRE_CALL(userRequestStub,
                 getUsers(ANY(gsl::span<Trustchain::DeviceId const>)))
        // FIXME
        .RETURN(makeCoTask(builder.entries()));

    auto const result = AWAIT(groupAccessor.getPublicEncryptionKeys(
        {aliceGroup.group.tankerGroup.id}));

    CHECK(result.notFound.empty());
    REQUIRE_EQ(result.found.size(), 1);
    CHECK_EQ(result.found[0],
             aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey);
  }

  SUBCASE("it fails request internal groups when are not part of")
  {
    REQUIRE_CALL(
        requestStub,
        getGroupBlocks(std::vector<GroupId>{bobGroup.group.tankerGroup.id}))
        .RETURN(
            makeCoTask(std::vector<Trustchain::ServerEntry>{bobGroup.entry}));
    REQUIRE_CALL(userRequestStub,
                 getUsers(ANY(gsl::span<Trustchain::DeviceId const>)))
        // FIXME
        .RETURN(makeCoTask(builder.entries()));

    auto const result =
        AWAIT(groupAccessor.getInternalGroups({bobGroup.group.tankerGroup.id}));

    CHECK(result.found.empty());
    REQUIRE_EQ(result.notFound.size(), 1);
    CHECK_EQ(result.notFound[0], bobGroup.group.tankerGroup.id);
  }

  SUBCASE("it should request internal groups by groupId if not in store")
  {
    REQUIRE_CALL(
        requestStub,
        getGroupBlocks(std::vector<GroupId>{aliceGroup.group.tankerGroup.id}))
        .RETURN(
            makeCoTask(std::vector<Trustchain::ServerEntry>{aliceGroup.entry}));
    REQUIRE_CALL(userRequestStub,
                 getUsers(ANY(gsl::span<Trustchain::DeviceId const>)))
        // FIXME
        .RETURN(makeCoTask(builder.entries()));

    auto const result = AWAIT(
        groupAccessor.getInternalGroups({aliceGroup.group.tankerGroup.id}));

    CHECK(result.notFound.empty());
    REQUIRE_EQ(result.found.size(), 1);
    CHECK_EQ(result.found[0], aliceGroup.group.tankerGroup);
  }

  SUBCASE("it fails to get group encryption key pairs if not in group")
  {
    REQUIRE_CALL(
        requestStub,
        getGroupBlocks(bobGroup.group.tankerGroup.encryptionKeyPair.publicKey))
        .RETURN(
            makeCoTask(std::vector<Trustchain::ServerEntry>{bobGroup.entry}));
    REQUIRE_CALL(userRequestStub,
                 getUsers(ANY(gsl::span<Trustchain::DeviceId const>)))
        // FIXME
        .RETURN(makeCoTask(builder.entries()));

    auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(
        bobGroup.group.tankerGroup.encryptionKeyPair.publicKey));

    CHECK_EQ(encryptionKeyPair, std::nullopt);
  }

  SUBCASE(
      "it should request group encryption key pairs by publicEncryptionKey if "
      "not in store")
  {
    REQUIRE_CALL(requestStub,
                 getGroupBlocks(
                     aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey))
        .RETURN(
            makeCoTask(std::vector<Trustchain::ServerEntry>{aliceGroup.entry}));
    REQUIRE_CALL(userRequestStub,
                 getUsers(ANY(gsl::span<Trustchain::DeviceId const>)))
        // FIXME
        .RETURN(makeCoTask(builder.entries()));

    auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(
        aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey));

    CHECK_EQ(encryptionKeyPair.value(),
             aliceGroup.group.tankerGroup.encryptionKeyPair);
  }
}
