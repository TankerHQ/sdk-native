#include <benchmark/benchmark.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/TrustchainFixture.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Config.hpp>

#include <fmt/core.h>

#include "BenchHelpers.hpp"

using namespace std::string_literals;

using namespace Tanker::Functional;

auto const benchAppId = Tanker::TestConstants::benchmarkApp().appId;
auto const benchAppSecret = Tanker::TestConstants::benchmarkApp().appSecret;

// What: creates a group
// PreCond: a session is open
// PostCond: a group is created
static void createGroup(benchmark::State& state)
{
  std::vector<Tanker::SPublicIdentity> publicIdentities;
  for (auto i = 0; i < state.range(0); ++i)
    publicIdentities.push_back(
        Tanker::SPublicIdentity(makePublicIdentity(benchAppId, i)));

  auto const identity = Tanker::Identity::createIdentity(
      benchAppId,
      benchAppSecret,
      createRandomUserId());
  auto device = Device(getTrustchain().url, benchAppId, identity);
  auto tanker = AWAIT(device.open());

  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
      TC_AWAIT(tanker->createGroup(publicIdentities));
  }).get();
}
BENCHMARK(createGroup)
    ->Arg(1)
    ->Arg(100)
    ->Arg(1000)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: adds members to a group
// PreCond: a session is open and a group was created
// PostCond: members were added to the group
static void updateGroupMembers_addMembers(benchmark::State& state)
{
  std::vector<Tanker::SPublicIdentity> publicIdentities;
  for (auto i = 0; i < state.range(0); ++i)
    publicIdentities.push_back(
        Tanker::SPublicIdentity(makePublicIdentity(benchAppId, i)));

  auto const identity = Tanker::Identity::createIdentity(
      benchAppId,
      benchAppSecret,
      createRandomUserId());
  auto device = Device(getTrustchain().url, benchAppId, identity);
  auto tanker = AWAIT(device.open());
  auto const groupId = AWAIT(tanker->createGroup({Tanker::SPublicIdentity(
      Tanker::Identity::getPublicIdentity(identity))}));

  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
      TC_AWAIT(tanker->updateGroupMembers(groupId, publicIdentities, {}));
  }).get();
}
BENCHMARK(updateGroupMembers_addMembers)
    ->Arg(1000)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: remove members from a group
// PreCond: a session is open and a group was created with members
// PostCond: members were removed from the group
static void updateGroupMembers_removeMembers(benchmark::State& state)
{
  std::vector<Tanker::SPublicIdentity> publicIdentitiesInGroup;
  for (auto i = 0; i < state.range(0); ++i)
    publicIdentitiesInGroup.push_back(
        Tanker::SPublicIdentity(makePublicIdentity(benchAppId, i)));

  std::vector<Tanker::SPublicIdentity> publicIdentitiesToRemove;
  std::copy_n(publicIdentitiesInGroup.begin(),
              state.range(1),
              std::back_inserter(publicIdentitiesToRemove));

  auto const identity = Tanker::Identity::createIdentity(
      benchAppId,
      benchAppSecret,
      createRandomUserId());
  auto device = Device(getTrustchain().url, benchAppId, identity);
  auto tanker = AWAIT(device.open());

  auto publicIdentitiesAndMe = publicIdentitiesInGroup;
  publicIdentitiesAndMe.push_back(
      Tanker::SPublicIdentity(Tanker::Identity::getPublicIdentity(identity)));

  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto const groupId = TC_AWAIT(tanker->createGroup(publicIdentitiesAndMe));
      state.ResumeTiming();

      TC_AWAIT(
          tanker->updateGroupMembers(groupId, {}, publicIdentitiesToRemove));
    }
  }).get();
}
BENCHMARK(updateGroupMembers_removeMembers)
    ->Args({1, 1})
    ->Args({999, 999})
    ->Args({999, 1})
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: shares a resource with a cached group
// PreCond: a session is open, a resource was encrypted and the group is in the
//  cache
// PostCond: the resource is shared with the groups
static void share_withGroup(benchmark::State& state, std::string const& groupId)
{
  tc::async_resumable([&]() -> tc::cotask<void> {
    auto const identity = Tanker::Identity::createIdentity(
        benchAppId,
        benchAppSecret,
        createRandomUserId());
    auto device = Device(getTrustchain().url, benchAppId, identity);
    auto tanker = TC_AWAIT(device.open());

    // warm up the cache
    TC_AWAIT(tanker->encrypt(
        gsl::make_span("make some noise").as_span<uint8_t const>(),
        {},
        {Tanker::SGroupId{groupId}}));

    for (auto _ : state)
    {
      state.PauseTiming();
      auto const encryptedData = TC_AWAIT(tanker->encrypt(
          gsl::make_span("make some noise").as_span<uint8_t const>()));
      auto const resourceId = TC_AWAIT(tanker->getResourceId(encryptedData));
      state.ResumeTiming();

      TC_AWAIT(tanker->share({resourceId}, {}, {Tanker::SGroupId{groupId}}));
    }
  }).get();
}
BENCHMARK_CAPTURE(share_withGroup,
                  4000,
                  "8EySxOOyXktHkSOOgGAKCBRvIalV2iFObPGHk1QU63Q=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

static constexpr auto share_withGroupMultiAuthor = share_withGroup;
BENCHMARK_CAPTURE(share_withGroupMultiAuthor,
                  4000,
                  "rD3EO/d4S8dI20aybJUZcGiACV5kD298K8szq6ZWm0w=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: shares a resource with a group
// PreCond: a session is open and a resource was encrypted
// PostCond: the resource is shared with the groups
static void share_nocache_withGroup(benchmark::State& state,
                                    std::string const& groupId)
{
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto const identity = Tanker::Identity::createIdentity(
          benchAppId,
          benchAppSecret,
          createRandomUserId());
      auto device = Device(getTrustchain().url, benchAppId, identity);
      auto tanker = TC_AWAIT(device.open());
      auto const encryptedData = TC_AWAIT(tanker->encrypt(
          gsl::make_span("make some noise").as_span<uint8_t const>()));
      auto const resourceId = TC_AWAIT(tanker->getResourceId(encryptedData));
      state.ResumeTiming();

      TC_AWAIT(tanker->share({resourceId}, {}, {Tanker::SGroupId{groupId}}));

      state.PauseTiming();
      tanker = nullptr;
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK_CAPTURE(share_nocache_withGroup,
                  4000,
                  "8EySxOOyXktHkSOOgGAKCBRvIalV2iFObPGHk1QU63Q=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
