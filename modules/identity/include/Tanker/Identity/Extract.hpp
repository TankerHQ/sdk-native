#pragma once

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
namespace detail
{
nlohmann::json extract(std::string const& token);
}

template <typename I>
I extract(std::string const& token)
{
  return detail::extract(token).get<I>();
}
}
}
