#pragma once

#include <fmt/format.h>

#include <boost/utility/string_view_fwd.hpp>

namespace fmt
{
template <typename charT, typename traits>
struct formatter<boost::basic_string_view<charT, traits>, char>
  : formatter<std::basic_string_view<charT, traits>>
{
  using base_t = formatter<std::basic_string_view<charT, traits>>;

  template <typename FormatContext>
  auto format(boost::basic_string_view<charT, traits> bsv, FormatContext& ctx)
  {
    return base_t::format(
        std::basic_string_view<charT, traits>{bsv.data(), bsv.size()}, ctx);
  }
};
}
