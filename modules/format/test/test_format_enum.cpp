#include <Tanker/Format/Enum.hpp>

#include <catch2/catch_test_macros.hpp>
#include <fmt/core.h>

#include <string>

namespace
{
enum class Test
{
  One = 1,
  Two = 2
};

std::string to_string(Test t)
{
  switch (t)
  {
  case Test::One:
    return "One";
  case Test::Two:
    return "Two";
  default:
    return "INVALID";
  }
}
}

TEST_CASE("Formatting an enum")
{
  CHECK(fmt::format("my enum {}", Test::One) == R"!(my enum 1 One)!");
  CHECK(fmt::format("my enum {:}", Test::Two) == R"!(my enum 2 Two)!");
  CHECK(fmt::format("my enum {:s}", Test::Two) == R"!(my enum Two)!");
  CHECK(fmt::format("my enum {:d}", Test::Two) == R"!(my enum 2)!");
  CHECK(fmt::format("my enum {:e}", Test::One) == R"!(my enum 1 One)!");
}
