#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "GroupRequesterStub.hpp"
#include "LocalUserAccessorMock.hpp"
#include "ProvisionalUsersAccessorMock.hpp"
#include "TrustchainGenerator.hpp"
#include "UserAccessorMock.hpp"

#include <doctest/doctest.h>
#include <trompeloeil.hpp>

using namespace Tanker;
using Tanker::Trustchain::GroupId;

namespace
{
auto makeEntries = [](auto const& item) { return item.entries(); };
}

TEST_CASE("GroupAccessor")
{
  auto db = AWAIT(DataStore::createDatabase(":memory:"));
  Groups::Store groupStore(&db);

  Test::Generator generator;

  auto const alice = generator.makeUser("alice");
  auto const aliceGroup = alice.makeGroup();
  auto const bob = generator.makeUser("bob");
  auto const bobGroup = bob.makeGroup();

  GroupRequesterStub requestStub;
  UserAccessorMock aliceUserAccessorMock;
  ProvisionalUsersAccessorMock aliceProvisionalUsersAccessor{};
  LocalUserAccessorMock aliceLocalAccessorMock{};

  Groups::Accessor groupAccessor(&requestStub,
                                 &aliceUserAccessorMock,
                                 &groupStore,
                                 &aliceLocalAccessorMock,
                                 &aliceProvisionalUsersAccessor);

  SUBCASE("request groups in cache")
  {
    SUBCASE("it should return cached encryption keys")
    {

      AWAIT_VOID(groupStore.put(static_cast<InternalGroup>(aliceGroup)));

      auto const result1 =
          AWAIT(groupAccessor.getPublicEncryptionKeys({aliceGroup.id()}));
      CHECK_EQ(result1.found.at(0), aliceGroup.currentEncKp().publicKey);

      auto const result2 = AWAIT(groupAccessor.getEncryptionKeyPair(
          {aliceGroup.currentEncKp().publicKey}));
      CHECK_EQ(result2.value(), aliceGroup.currentEncKp());
    }

    SUBCASE("it can request group public keys by invalid groupId")
    {
      auto const unknownGroupId = make<GroupId>("unknownGroup");
      REQUIRE_CALL(requestStub,
                   getGroupBlocks(std::vector<GroupId>{unknownGroupId}))
          .RETURN(makeCoTask(std::vector<Trustchain::GroupAction>{}));

      auto const result =
          AWAIT(groupAccessor.getPublicEncryptionKeys({unknownGroupId}));

      CHECK(result.found.empty());
      REQUIRE_EQ(result.notFound.size(), 1);
      CHECK_EQ(result.notFound[0], unknownGroupId);
    }
  }

  SUBCASE("request groups *NOT* in cache")
  {
    auto const la = static_cast<Users::LocalUser>(alice);
    REQUIRE_CALL(aliceLocalAccessorMock, get()).LR_RETURN(la);
    REQUIRE_CALL(aliceProvisionalUsersAccessor, refreshKeys());

    SUBCASE("request group we are member of")
    {
      REQUIRE_CALL(aliceUserAccessorMock,
                   pull(std::vector{alice.devices().back().id()},
                        Users::IRequester::IsLight::Yes))
          .RETURN(
              makeCoTask(BasicPullResult<Users::Device, Trustchain::DeviceId>{
                  {alice.devices().front()}, {}}));
      REQUIRE_CALL(aliceLocalAccessorMock,
                   pullUserKeyPair(alice.userKeys().back().publicKey))
          .LR_RETURN(makeCoTask(std::make_optional(alice.userKeys().back())));

      SUBCASE("request group by Id")
      {
        REQUIRE_CALL(requestStub,
                     getGroupBlocks(std::vector<GroupId>{aliceGroup.id()}))
            .RETURN(makeCoTask(makeEntries(aliceGroup)));
        SUBCASE(
            "it should request group public keys by groupId if not in store")
        {
          auto const result =
              AWAIT(groupAccessor.getPublicEncryptionKeys({aliceGroup.id()}));

          CHECK(result.notFound.empty());
          REQUIRE_EQ(result.found.size(), 1);
          CHECK_EQ(result.found[0], aliceGroup.currentEncKp().publicKey);
        }

        SUBCASE("it should request internal groups by groupId if not in store")
        {
          auto const result =
              AWAIT(groupAccessor.getInternalGroups({aliceGroup.id()}));

          CHECK(result.notFound.empty());
          REQUIRE_EQ(result.found.size(), 1);
          CHECK_EQ(result.found[0], aliceGroup);
        }
      }

      SUBCASE(
          "it should request group encryption key pairs by publicEncryptionKey "
          "if not in store")
      {
        REQUIRE_CALL(requestStub,
                     getGroupBlocks(aliceGroup.currentEncKp().publicKey))
            .RETURN(makeCoTask(makeEntries(aliceGroup)));

        auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(
            aliceGroup.currentEncKp().publicKey));

        CHECK_EQ(encryptionKeyPair.value(), aliceGroup.currentEncKp());
      }
    }

    SUBCASE("Request group we are *NOT* part of")
    {
      REQUIRE_CALL(aliceUserAccessorMock,
                   pull(std::vector{bob.devices().back().id()},
                        Users::IRequester::IsLight::Yes))
          .RETURN(
              makeCoTask(BasicPullResult<Users::Device, Trustchain::DeviceId>{
                  {bob.devices().front()}, {}}));
      SUBCASE("it fails request internal groups when are not part of")
      {
        REQUIRE_CALL(requestStub,
                     getGroupBlocks(std::vector<GroupId>{bobGroup.id()}))
            .RETURN(makeCoTask(makeEntries(bobGroup)));
        auto const result =
            AWAIT(groupAccessor.getInternalGroups({bobGroup.id()}));

        CHECK(result.found.empty());
        REQUIRE_EQ(result.notFound.size(), 1);
        CHECK_EQ(result.notFound[0], bobGroup.id());
      }

      SUBCASE("it fails to get group encryption key pairs if not in group")
      {
        REQUIRE_CALL(requestStub,
                     getGroupBlocks(bobGroup.currentEncKp().publicKey))
            .RETURN(makeCoTask(makeEntries(bobGroup)));

        auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(
            bobGroup.currentEncKp().publicKey));

        CHECK_EQ(encryptionKeyPair, std::nullopt);
      }
    }
  }
}
