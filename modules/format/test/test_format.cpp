#include <Tanker/Format/Width.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker::Format;

TEST_CASE("Parsing width")
{
  {
    constexpr auto c_str = "42";
    CHECK(parseWidth(c_str) == std::pair<int, int>(42, 2));
  }

  {
    constexpr auto c_str = "000";
    CHECK(parseWidth(c_str) == std::pair<int, int>(0, 3));
  }

  {
    constexpr auto c_str = "00n";
    CHECK(parseWidth(c_str) == std::pair<int, int>(0, 2));
  }

  {
    constexpr auto c_str = "n";
    CHECK(parseWidth(c_str) == std::pair<int, int>(0, 0));
  }
}
