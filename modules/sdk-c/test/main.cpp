#define DOCTEST_CONFIG_IMPLEMENT

#include <Helpers/TimeoutTerminate.hpp>
#include <Tanker/Init.hpp>

#include <doctest.h>

#include <chrono>

using namespace std::chrono_literals;

int main(int argc, char* argv[])
{
  Tanker::init();

  Tanker::TimeoutTerminate tt(5min);

  doctest::Context context(argc, argv);
  return context.run();
}
