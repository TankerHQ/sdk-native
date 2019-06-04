#include <Tanker/Format/Json.hpp>

#include <doctest.h>
#include <fmt/core.h>
#include <nlohmann/json.hpp>

TEST_CASE("Formatting a json value")
{
  auto const json = nlohmann::json{{"key", "value"}};
  CHECK_EQ(fmt::format("my json {}", json), R"!(my json {"key":"value"})!");
  CHECK_EQ(fmt::format("my json {:}", json), R"!(my json {"key":"value"})!");
  CHECK_EQ(fmt::format("my json {:j}", json),
           R"!(my json {"key":"value"})!");
  CHECK_EQ(fmt::format("{:5j}", json),
           R"!({
     "key": "value"
})!");
}
