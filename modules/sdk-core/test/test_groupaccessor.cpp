#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Sqlite/Backend.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>
#include <Helpers/MakeCoTask.hpp>

#include "GroupRequesterStub.hpp"
#include "LocalUserAccessorMock.hpp"
#include "ProvisionalUsersAccessorMock.hpp"
#include "TrustchainGenerator.hpp"
#include "UserAccessorMock.hpp"

#include <catch2/catch_test_macros.hpp>
#include <trompeloeil.hpp>

using namespace Tanker;
using Tanker::Trustchain::GroupId;

namespace
{
auto makeEntries = [](auto const& item) { return item.entries(); };
}

TEST_CASE("GroupAccessor")
{
  auto db = DataStore::SqliteBackend().open(":memory:", ":memory:");
  Groups::Store groupStore({}, db.get());

  Test::Generator generator;

  auto const alice = generator.makeUser("alice");
  auto const aliceGroup = alice.makeGroup();
  auto const bob = generator.makeUser("bob");
  auto const bobGroup = bob.makeGroup();

  GroupRequesterStub requestStub;
  UserAccessorMock aliceUserAccessorMock;
  ProvisionalUsersAccessorMock aliceProvisionalUsersAccessor{};
  LocalUserAccessorMock aliceLocalAccessorMock{};

  Groups::Accessor groupAccessor(
      &requestStub, &aliceUserAccessorMock, &groupStore, &aliceLocalAccessorMock, &aliceProvisionalUsersAccessor);

  SECTION("request groups from cache")
  {
    SECTION("it should return cached encryption keys")
    {

      AWAIT_VOID(groupStore.put(static_cast<InternalGroup>(aliceGroup)));

      auto const result1 = AWAIT(groupAccessor.getPublicEncryptionKeys({aliceGroup.id()}));
      CHECK(result1.found.at(0) == aliceGroup.currentEncKp().publicKey);

      auto const result2 = AWAIT(groupAccessor.getEncryptionKeyPair({aliceGroup.currentEncKp().publicKey}));
      CHECK(result2.value() == aliceGroup.currentEncKp());
    }

    SECTION("it can request group public keys by invalid groupId")
    {
      auto const unknownGroupId = make<GroupId>("unknownGroup");
      REQUIRE_CALL(requestStub, getGroupBlocks(std::vector<GroupId>{unknownGroupId}))
          .RETURN(makeCoTask(std::vector<Trustchain::GroupAction>{}));

      auto const result = AWAIT(groupAccessor.getPublicEncryptionKeys({unknownGroupId}));

      CHECK(result.found.empty());
      REQUIRE(result.notFound.size() == 1);
      CHECK(result.notFound[0] == unknownGroupId);
    }

    SECTION("it should return cached public encryption keys")
    {
      FORBID_CALL(requestStub, getGroupBlocks(std::vector<GroupId>{aliceGroup.id()}));

      {
        auto aliceInternalGroup = static_cast<InternalGroup>(aliceGroup);
        AWAIT_VOID(groupStore.put(aliceInternalGroup));
      }

      auto const result1 = AWAIT(groupAccessor.getPublicEncryptionKeys({aliceGroup.id()}));
      CHECK(result1.found.at(0) == aliceGroup.currentEncKp().publicKey);

      auto const result2 = AWAIT(groupAccessor.getEncryptionKeyPair({aliceGroup.currentEncKp().publicKey}));
      CHECK(result2.value() == aliceGroup.currentEncKp());
    }
  }

  SECTION("request groups *NOT* from cache")
  {
    auto const la = static_cast<Users::LocalUser>(alice);
    REQUIRE_CALL(aliceLocalAccessorMock, get()).LR_RETURN(la);
    REQUIRE_CALL(aliceProvisionalUsersAccessor, refreshKeys())
#if TCONCURRENT_COROUTINES_TS
        .LR_RETURN(makeCoTask());
#else
        ;
#endif

    SECTION("request group we are member of")
    {
      REQUIRE_CALL(aliceUserAccessorMock,
                   pull(std::vector{alice.devices().back().id()}, Users::IRequester::IsLight::Yes))
          .RETURN(makeCoTask(BasicPullResult<Users::Device, Trustchain::DeviceId>{{alice.devices().front()}, {}}));
      REQUIRE_CALL(aliceLocalAccessorMock, pullUserKeyPair(alice.userKeys().back().publicKey))
          .LR_RETURN(makeCoTask(std::make_optional(alice.userKeys().back())));

      SECTION("request group by Id")
      {
        REQUIRE_CALL(requestStub, getGroupBlocks(std::vector<GroupId>{aliceGroup.id()}))
            .RETURN(makeCoTask(makeEntries(aliceGroup)));
        SECTION("it should request group public keys by groupId if not in store")
        {
          auto const result = AWAIT(groupAccessor.getPublicEncryptionKeys({aliceGroup.id()}));

          CHECK(result.notFound.empty());
          REQUIRE(result.found.size() == 1);
          CHECK(result.found[0] == aliceGroup.currentEncKp().publicKey);
        }

        SECTION("it should request internal groups by groupId if not in store")
        {
          auto const result = AWAIT(groupAccessor.getInternalGroup({aliceGroup.id()}));

          CHECK(result == aliceGroup);
        }
      }

      SECTION(
          "it should request group encryption key pairs by publicEncryptionKey "
          "if not in store")
      {
        REQUIRE_CALL(requestStub, getGroupBlocks(aliceGroup.currentEncKp().publicKey))
            .RETURN(makeCoTask(makeEntries(aliceGroup)));

        auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(aliceGroup.currentEncKp().publicKey));

        CHECK(encryptionKeyPair.value() == aliceGroup.currentEncKp());
      }
    }

    SECTION("Request group we are *NOT* part of")
    {
      REQUIRE_CALL(aliceUserAccessorMock, pull(std::vector{bob.devices().back().id()}, Users::IRequester::IsLight::Yes))
          .RETURN(makeCoTask(BasicPullResult<Users::Device, Trustchain::DeviceId>{{bob.devices().front()}, {}}));
      SECTION("it fails request internal groups when are not part of")
      {
        REQUIRE_CALL(requestStub, getGroupBlocks(std::vector<GroupId>{bobGroup.id()}))
            .RETURN(makeCoTask(makeEntries(bobGroup)));
        TANKER_CHECK_THROWS_WITH_CODE(AWAIT(groupAccessor.getInternalGroup({bobGroup.id()})),
                                      Errors::Errc::InvalidArgument);
      }

      SECTION("it fails to get group encryption key pairs if not in group")
      {
        REQUIRE_CALL(requestStub, getGroupBlocks(bobGroup.currentEncKp().publicKey))
            .RETURN(makeCoTask(makeEntries(bobGroup)));

        auto const encryptionKeyPair = AWAIT(groupAccessor.getEncryptionKeyPair(bobGroup.currentEncKp().publicKey));

        CHECK(encryptionKeyPair == std::nullopt);
      }
    }
  }
}
