#pragma once

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <gsl/gsl-lite.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

template <typename Str = char*>
Str duplicateString(std::string const& str)
{
  auto ret = static_cast<Str>(std::malloc(str.size() + 1));
  return std::strcpy(ret, str.c_str());
}

template <typename T = std::string>
inline auto to_vector(char const* const* tab, uint64_t size)
{
  return ranges::make_subrange(tab, tab + size) | ranges::to<std::vector<T>>;
}
