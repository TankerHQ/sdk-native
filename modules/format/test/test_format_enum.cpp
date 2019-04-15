#include <Tanker/Format/Enum.hpp>

#include <doctest.h>
#include <fmt/format.h>

// VERY IMPORTANT to include this:
// https://github.com/onqtam/doctest/issues/183
#include <ostream>
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
  CHECK_EQ(fmt::format("my enum {}", Test::One), R"!(my enum 1 One)!");
  CHECK_EQ(fmt::format("my enum {:}", Test::Two), R"!(my enum 2 Two)!");
  CHECK_EQ(fmt::format("my enum {:s}", Test::Two), R"!(my enum Two)!");
  CHECK_EQ(fmt::format("my enum {:d}", Test::Two), R"!(my enum 2)!");
  CHECK_EQ(fmt::format("my enum {:e}", Test::One), R"!(my enum 1 One)!");
}
