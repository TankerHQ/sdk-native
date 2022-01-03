#define CATCH_CONFIG_RUNNER

#include <catch2/catch.hpp>
#include <trompeloeil.hpp>

#include <Helpers/TimeoutTerminate.hpp>

using namespace std::literals::chrono_literals;

int main(int argc, char* argv[])
{
  Tanker::TimeoutTerminate tt(5min);
  trompeloeil::set_reporter([](trompeloeil::severity s,
                               const char* file,
                               unsigned long line,
                               std::string const& msg) {
    auto f = line ? file : "[file/line unavailable]";
    if (s == trompeloeil::severity::fatal)
      FAIL(f << ':' << line << ": " << msg);
    else
      FAIL_CHECK(f << ':' << line << ": " << msg);
  });

  Catch::Session context;

  return context.run(argc, argv);
}
