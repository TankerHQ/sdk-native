#include <Tanker/Format/Width.hpp>

#include <doctest/doctest.h>

using namespace Tanker::Format;

TEST_CASE("Parsing width")
{
  {
    constexpr auto c_str = "42";
    CHECK_EQ(parseWidth(c_str), std::pair<int, int>(42, 2));
  }

  {
    constexpr auto c_str = "000";
    CHECK_EQ(parseWidth(c_str), std::pair<int, int>(0, 3));
  }

  {
    constexpr auto c_str = "00n";
    CHECK_EQ(parseWidth(c_str), std::pair<int, int>(0, 2));
  }

  {
    constexpr auto c_str = "n";
    CHECK_EQ(parseWidth(c_str), std::pair<int, int>(0, 0));
  }
}
