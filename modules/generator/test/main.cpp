#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest.h>

#include <Helpers/TimeoutTerminate.hpp>
#include <Tanker/Init.hpp>

using namespace std::literals::chrono_literals;
int main(int argc, char* argv[])
{
  Tanker::init();
  Tanker::TimeoutTerminate tt(5min);

  doctest::Context context(argc, argv);
  return context.run();
}
