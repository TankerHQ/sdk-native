#include <Tanker/Init.hpp>

#include <Tanker/LogHandler.hpp>

#include <benchmark/benchmark.h>

#include <Helpers/Await.hpp>

#include <Tanker/Test/Functional/Trustchain.hpp>

#include <cstdio>
#include <string>
using namespace std::string_literals;

static void log_handler(Tanker::Log::Record const&)
{
}

int main(int argc, char** argv)
{
  Tanker::init();
  Tanker::Log::setLogHandler(&log_handler);
  AWAIT_VOID(Tanker::Test::Trustchain::getInstance().init());
  benchmark::Initialize(&argc, argv);
#ifdef TANKER_ENABLE_TRACER
  fmt::print("Waiting for input...");
  std::getchar();
#endif
  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
