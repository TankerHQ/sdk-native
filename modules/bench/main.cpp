#include <Tanker/Functional/TrustchainFixture.hpp>
#include <Tanker/Init.hpp>

#include <Tanker/Log/LogHandler.hpp>

#include <tconcurrent/thread_pool.hpp>

#include <benchmark/benchmark.h>

#include <Helpers/Await.hpp>

#include <cstdio>
#include <string>

using namespace std::string_literals;
using Tanker::Functional::TrustchainFixture;

static void log_handler(Tanker::Log::Record const&)
{
}

int main(int argc, char** argv)
{
  Tanker::init();
  Tanker::Log::setLogHandler(&log_handler);

  // We can't run the main coroutine on the default executor because each
  // benchmark is blocking and it would deadlock
  tc::thread_pool tp;
  tp.start(1);

  tc::async_resumable(
      "main_functional",
      tc::executor(tp),
      [&]() -> tc::cotask<void> {
        TC_AWAIT(TrustchainFixture::setUp());
        AWAIT_VOID(TrustchainFixture::trustchainFactory().enable2fa(
            TrustchainFixture{}.trustchain.id));
        benchmark::Initialize(&argc, argv);
#ifdef TANKER_ENABLE_TRACER
        fmt::print("Waiting for input...");
        std::getchar();
#endif
        benchmark::RunSpecifiedBenchmarks();
        TC_AWAIT(TrustchainFixture::tearDown());
      })
      .get();

  return 0;
}
