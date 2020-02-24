#define DOCTEST_CONFIG_IMPLEMENT

#include <doctest.h>
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
      ADD_FAIL_AT(f, line, msg);
    else
      ADD_FAIL_CHECK_AT(f, line, msg);
  });

  doctest::Context context(argc, argv);

  return context.run();
}
