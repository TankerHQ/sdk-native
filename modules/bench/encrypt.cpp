#include <benchmark/benchmark.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/TrustchainFixture.hpp>
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

// What: encrypts data
// PreCond: a session is open
// PostCond: the buffer is encrypted
static void encrypt(benchmark::State& state)
{
  auto& tr = getTrustchain();
  auto alice = tr.makeUser();
  auto device = alice.makeDevice();
  auto core = AWAIT(device.open());

  std::vector<uint8_t> buf(state.range(0));
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
      TC_AWAIT(core->encrypt(buf));
  }).get();
}
BENCHMARK(encrypt)
    ->Arg(32)
    ->Arg(2 * 1024 * 1024)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: shares a resource with users
// PreCond: a session is open and a resource was encrypted
// PostCond: the resource is shared with the users
static void share_withUsers(benchmark::State& state)
{
  std::vector<Tanker::SPublicIdentity> publicIdentities;
  for (auto i = 0; i < state.range(0); ++i)
    publicIdentities.push_back(
        Tanker::SPublicIdentity(makePublicIdentity(benchAppId, i)));

  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto const identity = Tanker::Identity::createIdentity(
          benchAppId,
          benchAppSecret,
          createRandomUserId());
      auto device = Device(getTrustchain().url, benchAppId, identity);
      auto core = TC_AWAIT(device.open());
      auto const encryptedData = TC_AWAIT(core->encrypt(
          gsl::make_span("make some noise").as_span<uint8_t const>()));
      auto const resourceId = TC_AWAIT(core->getResourceId(encryptedData));
      state.ResumeTiming();
      TC_AWAIT(core->share({resourceId}, publicIdentities, {}));
      state.PauseTiming();
      core.reset();
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK(share_withUsers)
    ->Arg(1)
    ->Arg(10)
    ->Arg(100)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
