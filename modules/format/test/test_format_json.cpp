#include <Tanker/Format/Json.hpp>

#include <catch2/catch.hpp>
#include <fmt/core.h>
#include <nlohmann/json.hpp>

TEST_CASE("Formatting a json value")
{
  auto const json = nlohmann::json{{"key", "value"}};
  CHECK(fmt::format("my json {}", json) == R"!(my json {"key":"value"})!");
  CHECK(fmt::format("my json {:}", json) == R"!(my json {"key":"value"})!");
  CHECK(fmt::format("my json {:j}", json) == R"!(my json {"key":"value"})!");
  CHECK(fmt::format("{:5j}", json) ==
        R"!({
     "key": "value"
})!");
}
