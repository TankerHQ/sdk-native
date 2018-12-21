#include <benchmark/benchmark.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/LogHandler.hpp>

#include <Helpers/Await.hpp>
#include <Tanker/Test/Functional/Trustchain.hpp>

#include <fmt/core.h>

using namespace std::string_literals;

using namespace Tanker::Test;

namespace
{
tc::cotask<std::vector<Tanker::SUserId>> createUsers(Trustchain& tr,
                                                     std::size_t nbUsers)
{
  auto res = std::vector<Tanker::SUserId>(nbUsers);
  for (auto i = 0u; i < nbUsers; ++i)
  {
    auto user = tr.makeUser(UserType::New);
    auto device = user.makeDevice();
    auto core = TC_AWAIT(device.open());
    TC_AWAIT(core->close());
    res[i] = device.suserId();
  }
  TC_RETURN(res);
}

auto create_encrypted(std::string const& plain_data)
{
  auto const size = Tanker::AsyncCore::encryptedSize(plain_data.size());
  std::basic_string<uint8_t> p(begin(plain_data), end(plain_data));
  std::basic_string<uint8_t> res;
  res.resize(size + 1);
  return std::make_pair(p, res);
}

tc::cotask<Tanker::SGroupId> createGroup(
    Trustchain& tr, std::vector<Tanker::SUserId> const& susers)
{
  auto alice = tr.makeUser();
  auto laptopDev = alice.makeDevice();
  auto laptop = TC_AWAIT(laptopDev.open());
  auto sgroupId = TC_AWAIT(laptop->createGroup(susers));
  TC_AWAIT(laptop->close());
  TC_RETURN(sgroupId);
}
}

/// What: open a session
/// PreCond: A core has been instanciated.
/// PostCond: Session is still open
static void open(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto alice = tr.makeUser(UserType::New);
      auto device = alice.makeDevice();
      auto core = device.createAsyncCore();
      state.ResumeTiming();
      TC_AWAIT(core->open(device.suserId(), device.userToken()));
      state.PauseTiming();
      core.reset();
      state.ResumeTiming();
    }
  })
      .get();
}
BENCHMARK(open)->Unit(benchmark::kMillisecond)->UseRealTime();

/// What: open then close
/// PreCond: A core has been instanciated.
/// PostCond: Session is closed, but not destroyed
static void open_close(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      state.PauseTiming();
      auto alice = tr.makeUser(UserType::New);
      auto device = alice.makeDevice();
      auto core = device.createAsyncCore();
      state.ResumeTiming();
      TC_AWAIT(core->open(device.suserId(), device.userToken()));
      TC_AWAIT(core->close());
      state.PauseTiming();
      core.reset();
      state.ResumeTiming();
    }
  })
      .get();
}
BENCHMARK(open_close)->Unit(benchmark::kMillisecond)->UseRealTime();

/// What: reopen a second device
/// PreCond: One session has be created and opened
/// PostCond: String is encrpted, session is still open
static void reopen(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  auto alice = tr.makeUser(UserType::New);
  auto device = alice.makeDevice();
  auto core = device.createCore(SessionType::New);
  AWAIT_VOID(core->open(device.suserId(), device.userToken()));
  AWAIT_VOID(core->close());
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
    {
      auto core = device.createCore(SessionType::New);
      TC_AWAIT(core->open(device.suserId(), device.userToken()));
      state.PauseTiming();
      TC_AWAIT(core->close());
      state.ResumeTiming();
    }
  })
      .get();
}
BENCHMARK(reopen)->Unit(benchmark::kMillisecond)->UseRealTime();

/// What: create and open a second device
/// PreCond: first session/device has be created and opened
/// PostCond: Everything is closed
static void multi(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  auto alice = tr.makeUser(UserType::New);
  auto laptop = alice.makeDevice();
  auto core = laptop.createCore(SessionType::New);
  tc::async_resumable([&]() -> tc::cotask<void> {
    TC_AWAIT(core->open(laptop.suserId(), laptop.userToken()));
    TC_AWAIT(laptop.registerUnlock(*core));
    for (auto _ : state)
    {
      state.PauseTiming();
      auto phone = alice.makeDevice();
      state.ResumeTiming();
      auto newcore = TC_AWAIT(phone.open(SessionType::New));
      TC_AWAIT(newcore->close());
      state.PauseTiming();
      TC_AWAIT(core->close());
      state.ResumeTiming();
    }
  })
      .get();
}
BENCHMARK(multi)->Unit(benchmark::kMillisecond)->UseRealTime();

/// What: Encrypt a string, which share to our only one device
/// PreCond: One session has be created and opened
/// PostCond: String is encrpted, session is still open
static void encrypt(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  auto alice = tr.makeUser(UserType::New);
  auto laptop = alice.makeDevice();
  auto core = laptop.createCore(SessionType::New);
  AWAIT_VOID(core->open(laptop.suserId(), laptop.userToken()));
  auto p = create_encrypted("this is my secret message");
  tc::async_resumable([&]() -> tc::cotask<void> {
    for (auto _ : state)
      for (auto i = 0; i < state.range(0); ++i)
        TC_AWAIT(core->encrypt(&p.second[0], p.first));
  })
      .get();
  AWAIT_VOID(core->close());
}
BENCHMARK(encrypt)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

/// What: Create a group
/// PreCond: All users are created and we create a group to pull and verify the
/// PostCond: group is created
static void create_group(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  auto alice = tr.makeUser(UserType::New);
  auto laptopDev = alice.makeDevice();
  auto laptop = laptopDev.createCore(SessionType::New);
  tc::async_resumable([&]() -> tc::cotask<void> {
    TC_AWAIT(laptop->open(laptopDev.suserId(), laptopDev.userToken()));
    auto users = TC_AWAIT(createUsers(tr, state.range(0)));
    // First hit to pull and verify the users
    TC_AWAIT(laptop->createGroup(users));
    for (auto _ : state)
      TC_AWAIT(laptop->createGroup(users));
  })
      .get();
  AWAIT_VOID(laptop->close());
}
BENCHMARK(create_group)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

/// What: Create a new user and create a group
/// PreCond: All users are created
/// PostCond: group is created
static void pull_and_create_group(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    auto users = TC_AWAIT(createUsers(tr, state.range(0)));
    for (auto _ : state)
    {
      state.PauseTiming();
      auto alice = tr.makeUser(UserType::New);
      auto laptopDev = alice.makeDevice();
      auto laptop = laptopDev.createAsyncCore();
      state.ResumeTiming();
      TC_AWAIT(laptop->open(laptopDev.suserId(), laptopDev.userToken()));
      TC_AWAIT(laptop->createGroup(users));
      state.PauseTiming();
      TC_AWAIT(laptop->close());
      laptop.reset();
      state.ResumeTiming();
    }
  })
      .get();
}
BENCHMARK(pull_and_create_group)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

/// What: share to N unverified users
/// PreCond: All users are created, but unknow to the session
/// PostCond: resource is shared to the users
static void share_to_unverified_users(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    auto users = TC_AWAIT(createUsers(tr, state.range(0)));
    auto p = create_encrypted("a");
    for (auto _ : state)
    {
      state.PauseTiming();
      auto alice = tr.makeUser(UserType::New);
      auto laptopDev = alice.makeDevice();
      auto laptop = laptopDev.createAsyncCore();
      TC_AWAIT(laptop->open(laptopDev.suserId(), laptopDev.userToken()));
      state.ResumeTiming();
      TC_AWAIT(laptop->encrypt(&p.second[0], p.first, users));
      state.PauseTiming();
      TC_AWAIT(laptop->close());
      laptop.reset();
      state.ResumeTiming();
    }
  })
      .get();
}
BENCHMARK(share_to_unverified_users)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

/// What: share to N users
/// PreCond: All users are created and known
/// PostCond: resource is shared to the users
static void share_to_users(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    auto users = TC_AWAIT(createUsers(tr, state.range(0)));
    auto p = create_encrypted("a");
    auto alice = tr.makeUser(UserType::New);
    auto laptopDev = alice.makeDevice();
    auto laptop = laptopDev.createCore(SessionType::New);
    TC_AWAIT(laptop->open(laptopDev.suserId(), laptopDev.userToken()));

    // we trigger the verification
    TC_AWAIT(laptop->encrypt(&p.second[0], p.first, users));
    for (auto _ : state)
      TC_AWAIT(laptop->encrypt(&p.second[0], p.first, users));
    TC_AWAIT(laptop->close());
  })
      .get();
}
BENCHMARK(share_to_users)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

/// What: share to a group
/// PreCond: group are created
/// PostCond: resource is shared to the group
static void share_to_group(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    auto users = TC_AWAIT(createUsers(tr, state.range(0)));
    auto p = create_encrypted("a");
    auto sgroupId = TC_AWAIT(createGroup(tr, users));

    auto alice = tr.makeUser(UserType::New);
    auto laptopDev = alice.makeDevice();
    auto laptop = laptopDev.createCore(SessionType::New);
    TC_AWAIT(laptop->open(laptopDev.suserId(), laptopDev.userToken()));
    // trigger the verification
    TC_AWAIT(laptop->encrypt(&p.second[0], p.first, {}, {sgroupId}));
    for (auto _ : state)
      TC_AWAIT(laptop->encrypt(&p.second[0], p.first, {}, {sgroupId}));
  })
      .get();
}
BENCHMARK(share_to_group)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

/// What: share to an unverified group
/// PreCond: group are created and not known
/// PostCond: resource is shared to the users
static void share_to_unverified_group(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    auto users = TC_AWAIT(createUsers(tr, state.range(0)));
    auto p = create_encrypted("a");
    auto sgroupId = TC_AWAIT(createGroup(tr, users));

    for (auto _ : state)
    {
      state.PauseTiming();
      auto alice = tr.makeUser(UserType::New);
      auto laptopDev = alice.makeDevice();
      auto laptop = laptopDev.createAsyncCore();
      TC_AWAIT(laptop->open(laptopDev.suserId(), laptopDev.userToken()));
      state.ResumeTiming();
      TC_AWAIT(laptop->encrypt(&p.second[0], p.first, {}, {sgroupId}));
      state.PauseTiming();
      TC_AWAIT(laptop->close());
      laptop.reset();
      state.ResumeTiming();
    }
  })
      .get();
}
BENCHMARK(share_to_unverified_group)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();

/// What: add to a group
/// PreCond: group are created known
/// PostCond: resource is shared to the users
static void add_to_group(benchmark::State& state)
{
  auto& tr = Trustchain::getInstance();
  tc::async_resumable([&]() -> tc::cotask<void> {
    auto p = create_encrypted("a");

    auto users = TC_AWAIT(createUsers(tr, state.range(0)));

    auto alice = tr.makeUser(UserType::New);
    auto laptopDev = alice.makeDevice();
    auto laptop = laptopDev.createCore(SessionType::New);
    TC_AWAIT(laptop->open(laptopDev.suserId(), laptopDev.userToken()));
    auto sgroupId = TC_AWAIT(laptop->createGroup({alice.suserId()}));

    for (auto _ : state)
      TC_AWAIT(laptop->updateGroupMembers(sgroupId, users));
  })
      .get();
}
BENCHMARK(add_to_group)
    ->Arg(1)
    ->Arg(20)
    ->Unit(benchmark::kMillisecond)
    ->UseRealTime();
