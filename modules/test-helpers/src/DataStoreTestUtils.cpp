#include <Helpers/DataStoreTestUtils.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <cstring>

std::vector<std::pair<gsl::span<uint8_t const>, gsl::span<uint8_t const>>>
makeKeyValues(std::vector<std::pair<std::string_view, std::string_view>> vals)
{
  return vals | ranges::views::transform([](auto const& v) {
           return std::pair{
               gsl::make_span(v.first).template as_span<uint8_t const>(),
               gsl::make_span(v.second).template as_span<uint8_t const>()};
         }) |
         ranges::to<std::vector>;
}

std::vector<gsl::span<uint8_t const>> makeKeys(std::vector<char const*> keys)
{
  return keys | ranges::views::transform([](char const* v) {
           return gsl::span(v, strlen(v)).as_span<uint8_t const>();
         }) |
         ranges::to<std::vector>;
}
