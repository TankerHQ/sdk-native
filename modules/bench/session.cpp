#include <benchmark/benchmark.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/TrustchainFixture.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Helpers/Await.hpp>

#include <fmt/core.h>

#include "BenchHelpers.hpp"

using namespace std::string_literals;

using namespace Tanker::Functional;

// What: starts and registers an identity with a verification key
// PreCond: a core as been constructed
// PostCond: a session is open
static void registerIdentity_verificationKey(benchmark::State& state)
{
  auto& tr = getTrustchain();
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto alice = tr.makeUser(UserType::New);
      auto device = alice.makeDevice();
      auto core = device.createAsyncCore();
      state.ResumeTiming();
      TC_AWAIT(core->start(device.identity()));
      auto const verificationKey = TC_AWAIT(core->generateVerificationKey());
      TC_AWAIT(core->registerIdentity(verificationKey));
      state.PauseTiming();
      core.reset();
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK(registerIdentity_verificationKey)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: starts and registers an identity with a passphrase
// PreCond: a core as been constructed
// PostCond: a session is open
static void registerIdentity_passphrase(benchmark::State& state)
{
  auto& tr = getTrustchain();
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto alice = tr.makeUser(UserType::New);
      auto device = alice.makeDevice();
      auto core = device.createAsyncCore();
      state.ResumeTiming();
      TC_AWAIT(core->start(device.identity()));
      TC_AWAIT(core->registerIdentity(Tanker::Passphrase{"strong password"}));
      state.PauseTiming();
      core.reset();
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK(registerIdentity_passphrase)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: starts an already registered device
// PreCond: an identity has been registered with this device
// PostCond: a session is open
static void start_noVerification(benchmark::State& state)
{
  auto& tr = getTrustchain();
  auto alice = tr.makeUser(UserType::New);
  auto device = alice.makeDevice();
  auto core = device.createCore(SessionType::New);
  AWAIT_VOID(core->start(device.identity()));
  auto const verificationKey = AWAIT(core->generateVerificationKey());
  AWAIT_VOID(core->registerIdentity(verificationKey));
  AWAIT_VOID(core->stop());
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      TC_AWAIT(core->start(device.identity()));
      state.PauseTiming();
      TC_AWAIT(core->stop());
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK(start_noVerification)->Unit(benchmark::kMillisecond)->UseRealTime();

// What: stops an open session
// PreCond: a session is open
// PostCond: the session is closed
static void stop(benchmark::State& state)
{
  auto& tr = getTrustchain();
  auto alice = tr.makeUser(UserType::New);
  auto device = alice.makeDevice();
  auto core = device.createCore(SessionType::New);
  AWAIT_VOID(core->start(device.identity()));
  auto const verificationKey = AWAIT(core->generateVerificationKey());
  AWAIT_VOID(core->registerIdentity(verificationKey));
  AWAIT_VOID(core->stop());
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      TC_AWAIT(core->start(device.identity()));
      state.ResumeTiming();
      TC_AWAIT(core->stop());
    }
  }).get();
}
BENCHMARK(stop)->Unit(benchmark::kMillisecond)->UseRealTime();

// What: starts and verifies an identity with a verification key
// PreCond: an identity was registered with another device
// PostCond: the session is open
static void verifyIdentity_verificationKey(benchmark::State& state)
{
  auto& tr = getTrustchain();
  auto alice = tr.makeUser(UserType::New);
  auto device = alice.makeDevice();
  auto core = device.createCore(SessionType::New);
  AWAIT_VOID(core->start(device.identity()));
  auto const verificationKey = AWAIT(core->generateVerificationKey());
  AWAIT_VOID(core->registerIdentity(verificationKey));
  AWAIT_VOID(core->stop());
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto device2 = alice.makeDevice();
      auto core2 = device2.createCore(SessionType::New);
      state.ResumeTiming();
      TC_AWAIT(core2->start(alice.identity));
      TC_AWAIT(core2->verifyIdentity(verificationKey));
      state.PauseTiming();
      core2.reset();
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK(verifyIdentity_verificationKey)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: starts and verifies an identity with a passphrase
// PreCond: an identity was registered with another device
// PostCond: the session is open
static void verifyIdentity_passphrase(benchmark::State& state)
{
  auto& tr = getTrustchain();
  auto alice = tr.makeUser(UserType::New);
  auto device = alice.makeDevice();
  auto core = device.createCore(SessionType::New);
  AWAIT_VOID(core->start(device.identity()));
  AWAIT_VOID(core->registerIdentity(Tanker::Passphrase{"passphrase"}));
  AWAIT_VOID(core->stop());
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto device2 = alice.makeDevice();
      auto core2 = device2.createCore(SessionType::New);
      state.ResumeTiming();
      TC_AWAIT(core2->start(alice.identity));
      TC_AWAIT(core2->verifyIdentity(Tanker::Passphrase{"passphrase"}));
      state.PauseTiming();
      core2.reset();
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK(verifyIdentity_passphrase)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

// What: starts and verifies an identity with a passphrase and asks for a
// session token
// PreCond: an identity was registered with another device
// PostCond: the session is open and we have a session token
static void verifyIdentity_passphrase_withToken(benchmark::State& state)
{
  auto& tr = getTrustchain();
  auto alice = tr.makeUser(UserType::New);
  auto device = alice.makeDevice();
  auto core = device.createCore(SessionType::New);
  AWAIT_VOID(core->start(device.identity()));
  AWAIT_VOID(core->registerIdentity(Tanker::Passphrase{"passphrase"}));
  AWAIT_VOID(core->stop());
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto device2 = alice.makeDevice();
      auto core2 = device2.createCore(SessionType::New);
      state.ResumeTiming();
      TC_AWAIT(core2->start(alice.identity));
      TC_AWAIT(core2->verifyIdentity(Tanker::Passphrase{"passphrase"},
                                     Tanker::Core::VerifyWithToken::Yes));
      state.PauseTiming();
      core2.reset();
      state.ResumeTiming();
    }
  }).get();
}
BENCHMARK(verifyIdentity_passphrase_withToken)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
