#include <benchmark/benchmark.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/TrustchainFixture.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Config.hpp>

#include <fmt/core.h>
#include <sodium/randombytes.h>

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
      Tanker::SUserId(std::to_string(randombytes_random())));
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
      Tanker::SUserId(std::to_string(randombytes_random())));
  auto device = Device(getTrustchain().url, benchAppId, identity);
  auto tanker = AWAIT(device.open());
  auto const groupId = AWAIT(tanker->createGroup({Tanker::SPublicIdentity(
      Tanker::Identity::getPublicIdentity(identity))}));

  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
      TC_AWAIT(tanker->updateGroupMembers(groupId, publicIdentities));
  }).get();
}
BENCHMARK(updateGroupMembers_addMembers)
    ->Arg(1000)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: shares a resource with groups
// PreCond: a session is open and a resource was encrypted
// PostCond: the resource is shared with the groups
static void share_withGroup(benchmark::State& state, std::string const& groupId)
{
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto const identity = Tanker::Identity::createIdentity(
          benchAppId,
          benchAppSecret,
          Tanker::SUserId(std::to_string(randombytes_random())));
      auto device = Device(getTrustchain().url, benchAppId, identity);
      auto tanker = TC_AWAIT(device.open(SessionType::New));
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
BENCHMARK_CAPTURE(share_withGroup,
                  1,
                  "80ngpVLQ8cfglO5cC7I6a2Ph5QRfKPUVkXWOul5e6RM=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
BENCHMARK_CAPTURE(share_withGroup,
                  100,
                  "XhMfSCnOhMlW/KSt5k33eD/FoGG09MRI/6JT8q/YDK0=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
BENCHMARK_CAPTURE(share_withGroup,
                  1000,
                  "dzNO6xPpz9r2Wpe2Xxdl+9WiO6E/m8GVhv0RwvUcc0Q=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
BENCHMARK_CAPTURE(share_withGroup,
                  4000,
                  "/2fnEK7f7d82WECEvjvoC3T1DgFR0ZGMZkgJji33FwA=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

static constexpr auto share_withGroupMultiAuthor = share_withGroup;
BENCHMARK_CAPTURE(share_withGroupMultiAuthor,
                  100,
                  "n08iCwU+/QYAPKCqDBPD4dUK2oVyO1V3EwB3fo7Yz6U=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
BENCHMARK_CAPTURE(share_withGroupMultiAuthor,
                  1000,
                  "XyR77EErpEZ+ZCAjLTOQzUrH5dfck6avsZPLvZ/Ebmc=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
BENCHMARK_CAPTURE(share_withGroupMultiAuthor,
                  4000,
                  "rD3EO/d4S8dI20aybJUZcGiACV5kD298K8szq6ZWm0w=")
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
