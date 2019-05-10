#include <Tanker/KeyPublishStore.hpp>

#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "TrustchainBuilder.hpp"

#include <doctest.h>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain;

TEST_CASE("KeyPublishStore")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));

  KeyPublishStore keyPublishes(dbPtr.get());

  SUBCASE("it should not find a non-existent key publish")
  {
    auto const unexistentResourceId = make<ResourceId>("unexistent");

    CHECK_EQ(AWAIT(keyPublishes.find(unexistentResourceId)), nonstd::nullopt);
  }

  SUBCASE("it should discard a second KeyPublish with an existing resource id")
  {
    Actions::KeyPublish kp1{Actions::KeyPublishToProvisionalUser{}};
    AWAIT_VOID(keyPublishes.put(kp1));
    Actions::KeyPublish kp2 = Actions::KeyPublishToUser{};
    AWAIT_VOID(keyPublishes.put(kp2));
    CHECK_EQ(AWAIT(keyPublishes.find({})), kp1);
  }

  SUBCASE("it should add and find a KeyPublish")
  {
    Actions::KeyPublish const kp{Actions::KeyPublish::ToProvisionalUser{}};

    AWAIT_VOID(keyPublishes.put(kp));
    CHECK_EQ(AWAIT(keyPublishes.find({})), kp);
  }

  SUBCASE("it should add and find multiple KeyPublish")
  {
    auto const resourceId = make<ResourceId>("resource id");
    auto const resourceIdBis = make<ResourceId>("resource id bis");
    std::vector<Actions::KeyPublish> const kps{
        Actions::KeyPublish::ToProvisionalUser{{}, resourceIdBis, {}, {}},
        Actions::KeyPublish::ToDevice{{}, resourceId, {}}};

    AWAIT_VOID(keyPublishes.put(kps));
    CHECK_EQ(AWAIT(keyPublishes.find(resourceIdBis)), kps.front());
    CHECK_EQ(AWAIT(keyPublishes.find(resourceId)), kps.back());
  }
}
