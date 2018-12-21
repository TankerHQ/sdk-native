#include <Tanker/Init.hpp>

#include <Tanker/LogHandler.hpp>

#include <benchmark/benchmark.h>

#include <Helpers/Await.hpp>

#include <Tanker/Test/Functional/Trustchain.hpp>

#include <string>
using namespace std::string_literals;

static void log_handler(char const* cat, char level, char const* msg)
{
}

int main(int argc, char** argv)
{
  Tanker::init();
  Log::setLogHandler(&log_handler);
  AWAIT_VOID(Tanker::Test::Trustchain::getInstance().init());
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
