#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/TrustchainPuller.hpp>

#include <Helpers/Await.hpp>

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

template <typename T, typename U>
auto getMember(std::initializer_list<T> in, U member)
{
  std::vector<std::remove_reference_t<decltype(std::declval<T>().*member)>> out;
  out.reserve(in.size());
  std::transform(
      begin(in), end(in), std::back_inserter(out), [&](auto const& elem) {
        return elem.*member;
      });
  return out;
}
}

TEST_CASE("GroupAccessor")
{
  auto const dbPtr = AWAIT(DataStore::createDatabase(":memory:"));
  GroupStore groupStore(dbPtr.get());

  TrustchainBuilder builder;
  auto const ma = builder.makeUser3("ma");
  auto const morris = builder.makeUser3("morris");

  auto const averell = builder.makeUser3("averell");
  auto const jack = builder.makeUser3("jack");
  auto const william = builder.makeUser3("william");
  auto const joe = builder.makeUser3("joe");

  auto const dalton = builder.makeGroup(
      ma.user.devices.front(),
      getMember({averell, jack, william, joe}, &decltype(averell)::user));

  auto const luke = builder.makeUser3("lucky luke");
  auto const jolly = builder.makeUser3("jolly jumper");
  auto const rantanplan = builder.makeUser3("rantanplan");

  auto const goodguys = builder.makeGroup(
      ma.user.devices.front(),
      getMember({luke, jolly, rantanplan}, &decltype(luke)::user));

  mockaron::mock<TrustchainPuller, TrustchainPullerStub> trustchainPuller;
  GroupAccessor GroupAccessor({},
                              nullptr,
                              &trustchainPuller.get(),
                              nullptr,
                              &groupStore,
                              nullptr,
                              nullptr);

  SUBCASE("it should return external groups it did not find")
  {
    std::vector<GroupId> groups{dalton.group.tankerGroup.id};
    ALLOW_CALL(trustchainPuller.get_mock_impl(),
               scheduleCatchUp(trompeloeil::_, trompeloeil::_))
        .LR_RETURN(tc::make_ready_future());
    auto const result = AWAIT(GroupAccessor.pull(groups));
    CHECK_UNARY(result.found.empty());
    CHECK_EQ(result.notFound, groups);
  }

  SUBCASE("it should return found external group")
  {
    AWAIT_VOID(groupStore.put(dalton.group.asExternalGroup()));
    AWAIT_VOID(groupStore.put(goodguys.group.tankerGroup));

    std::vector<GroupId> groups{dalton.group.tankerGroup.id};

    ALLOW_CALL(trustchainPuller.get_mock_impl(),
               scheduleCatchUp(trompeloeil::_, trompeloeil::_))
        .LR_RETURN(tc::make_ready_future());

    auto const result = AWAIT(GroupAccessor.pull(groups));
    auto const dexternal = dalton.group.asExternalGroup();

    CHECK_EQ(result.found.at(0), dexternal);
  }

  SUBCASE("It should not fetch full group")
  {
    AWAIT_VOID(groupStore.put(dalton.group.asExternalGroup()));
    AWAIT_VOID(groupStore.put(goodguys.group.tankerGroup));

    std::vector<GroupId> groups{dalton.group.tankerGroup.id,
                                goodguys.group.tankerGroup.id};

    REQUIRE_CALL(
        trustchainPuller.get_mock_impl(),
        scheduleCatchUp(trompeloeil::_,
                        std::vector<GroupId>{dalton.group.tankerGroup.id}))
        .LR_RETURN(tc::make_ready_future());

    auto const result = AWAIT(GroupAccessor.pull(groups));
    auto const dexternal = dalton.group.asExternalGroup();
  }
}
