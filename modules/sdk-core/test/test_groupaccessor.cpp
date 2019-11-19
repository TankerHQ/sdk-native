#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Groups/Requests.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "TrustchainBuilder.hpp"

#include <doctest.h>
#include <mockaron/mockaron.hpp>
#include <trompeloeil.hpp>

using namespace Tanker;
using Tanker::Trustchain::GroupId;

namespace
{
class TrustchainPullerStub : public mockaron::mock_impl
{
public:
  TrustchainPullerStub()
  {
    MOCKARON_DECLARE_IMPL(TrustchainPuller, scheduleCatchUp);
  }

  MAKE_MOCK2(scheduleCatchUp,
             tc::shared_future<void>(std::vector<Trustchain::UserId>,
                                     std::vector<Trustchain::GroupId>));
};

class RequestMock : public mockaron::mock_impl
{
public:
  MAKE_MOCK2(getGroupBlocks,
             std::vector<Trustchain::ServerEntry>(
                 Client*, Crypto::PublicEncryptionKey const& key));
  MAKE_MOCK2(getGroupBlocks,
             std::vector<Trustchain::ServerEntry>(
                 Client*, std::vector<Trustchain::GroupId> const&));
};
}

TEST_CASE("GroupAccessor")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));
  GroupStore groupStore(dbPtr.get());

  TrustchainBuilder builder;
  auto const alice = builder.makeUser3("alice");
  auto const bob = builder.makeUser3("bob");

  auto const aliceGroup =
      builder.makeGroup(alice.user.devices.front(), {alice.user});
  auto const bobGroup = builder.makeGroup(bob.user.devices.front(), {bob.user});

  RequestMock requestMock;
  MOCKARON_SET_FUNCTION_IMPL_CUSTOM(
      tc::cotask<std::vector<Trustchain::ServerEntry>>(
          Client*, std::vector<Trustchain::GroupId> const&),
      std::vector<Trustchain::ServerEntry>,
      Groups::Requests::getGroupBlocks,
      [&](auto&&... args) {
        return requestMock.getGroupBlocks(
            std::forward<decltype(args)>(args)...);
      });
  MOCKARON_SET_FUNCTION_IMPL_CUSTOM(
      tc::cotask<std::vector<Trustchain::ServerEntry>>(
          Client*, Crypto::PublicEncryptionKey const&),
      std::vector<Trustchain::ServerEntry>,
      Groups::Requests::getGroupBlocks,
      [&](auto&&... args) {
        return requestMock.getGroupBlocks(
            std::forward<decltype(args)>(args)...);
      });
  ALLOW_CALL(requestMock,
             getGroupBlocks(trompeloeil::_, std::vector<GroupId>{}))
      .RETURN(std::vector<Trustchain::ServerEntry>{});

  mockaron::mock<TrustchainPuller, TrustchainPullerStub> trustchainPuller;
  auto const aliceContactStore =
      builder.makeContactStoreWith({"alice", "bob"}, dbPtr.get());
  auto const aliceUserKeyStore =
      builder.makeUserKeyStore(alice.user, dbPtr.get());
  GroupAccessor groupAccessor(alice.user.userId,
                              nullptr,
                              &trustchainPuller.get(),
                              aliceContactStore.get(),
                              &groupStore,
                              aliceUserKeyStore.get(),
                              nullptr);

  SUBCASE("it should return cached public encryption keys")
  {
    AWAIT_VOID(groupStore.put(aliceGroup.group.asExternalGroup()));

    auto const result = AWAIT(groupAccessor.getPublicEncryptionKeys(
        {aliceGroup.group.tankerGroup.id}));

    CHECK_EQ(result.found.at(0),
             aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey);
  }

  SUBCASE("it should return cached internal groups")
  {
    AWAIT_VOID(groupStore.put(aliceGroup.group.tankerGroup));

    auto const result = AWAIT(
        groupAccessor.getInternalGroups({aliceGroup.group.tankerGroup.id}));

    CHECK_EQ(result.found.at(0), aliceGroup.group.tankerGroup);
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
    REQUIRE_CALL(
        requestMock,
        getGroupBlocks(trompeloeil::_, std::vector<GroupId>{unknownGroupId}))
        .RETURN(std::vector<Trustchain::ServerEntry>{});

    auto const result =
        AWAIT(groupAccessor.getPublicEncryptionKeys({unknownGroupId}));

    CHECK(result.found.empty());
    REQUIRE_EQ(result.notFound.size(), 1);
    CHECK_EQ(result.notFound[0], unknownGroupId);
  }

  SUBCASE("it should request group public keys by groupId if not in store")
  {
    REQUIRE_CALL(
        requestMock,
        getGroupBlocks(trompeloeil::_,
                       std::vector<GroupId>{aliceGroup.group.tankerGroup.id}))
        .RETURN(std::vector<Trustchain::ServerEntry>{aliceGroup.entry});

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
        requestMock,
        getGroupBlocks(trompeloeil::_,
                       std::vector<GroupId>{bobGroup.group.tankerGroup.id}))
        .RETURN(std::vector<Trustchain::ServerEntry>{bobGroup.entry});

    auto const result =
        AWAIT(groupAccessor.getInternalGroups({bobGroup.group.tankerGroup.id}));

    CHECK(result.found.empty());
    REQUIRE_EQ(result.notFound.size(), 1);
    CHECK_EQ(result.notFound[0], bobGroup.group.tankerGroup.id);
  }

  SUBCASE("it should request internal groups by groupId if not in store")
  {
    REQUIRE_CALL(
        requestMock,
        getGroupBlocks(trompeloeil::_,
                       std::vector<GroupId>{aliceGroup.group.tankerGroup.id}))
        .RETURN(std::vector<Trustchain::ServerEntry>{aliceGroup.entry});

    auto const result = AWAIT(
        groupAccessor.getInternalGroups({aliceGroup.group.tankerGroup.id}));

    CHECK(result.notFound.empty());
    REQUIRE_EQ(result.found.size(), 1);
    CHECK_EQ(result.found[0], aliceGroup.group.tankerGroup);
  }

  SUBCASE("it fails to get group encryption key pairs if not in group")
  {
    REQUIRE_CALL(
        requestMock,
        getGroupBlocks(trompeloeil::_,
                       bobGroup.group.tankerGroup.encryptionKeyPair.publicKey))
        .RETURN(std::vector<Trustchain::ServerEntry>{bobGroup.entry});

    auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(
        bobGroup.group.tankerGroup.encryptionKeyPair.publicKey));

    CHECK_EQ(encryptionKeyPair, nonstd::nullopt);
  }

  SUBCASE(
      "it should request group encryption key pairs by publicEncryptionKey if "
      "not in store")
  {
    REQUIRE_CALL(requestMock,
                 getGroupBlocks(
                     trompeloeil::_,
                     aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey))
        .RETURN(std::vector<Trustchain::ServerEntry>{aliceGroup.entry});

    auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(
        aliceGroup.group.tankerGroup.encryptionKeyPair.publicKey));

    CHECK_EQ(encryptionKeyPair.value(),
             aliceGroup.group.tankerGroup.encryptionKeyPair);
  }
}
