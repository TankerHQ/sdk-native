#pragma once

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

template <typename Str = char*>
Str duplicateString(std::string const& str)
{
  auto ret = static_cast<Str>(std::malloc(str.size() + 1));
  return std::strcpy(ret, str.c_str());
}

template <typename T = std::string>
inline auto to_vector(char const* const* tab, uint64_t size)
{
  std::vector<T> res;
  res.reserve(size);
  std::transform(
      tab, std::next(tab, size), std::back_inserter(res), [](auto&& elem) {
        return T{elem};
      });
  return res;
}
