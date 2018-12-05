#define DOCTEST_CONFIG_IMPLEMENT

#include <doctest.h>
#include <trompeloeil/trompeloeil.hpp>

#include <Helpers/TimeoutTerminate.hpp>

using namespace std::literals::chrono_literals;

int main(int argc, char* argv[])
{
  Tanker::TimeoutTerminate tt(5min);
  trompeloeil::set_reporter([](trompeloeil::severity s,
                               const char* file,
                               unsigned long line,
                               std::string const& msg) {
    std::ostringstream os;
    if (line)
      os << file << ':' << line << '\n';
    os << msg;
    auto failure = os.str();
    if (s == trompeloeil::severity::fatal)
    {
      FAIL(failure);
    }
    else
    {
      CAPTURE(failure);
      CHECK(failure.empty());
    }
  });

  doctest::Context context(argc, argv);

  return context.run();
}
