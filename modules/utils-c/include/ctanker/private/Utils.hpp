#pragma once

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <gsl/gsl-lite.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

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
inline auto to_vector(char const* const* tab, uint64_t size, std::string_view fieldName)
{
  if (tab == nullptr && size != 0)
    throw formatEx(Tanker::Errors::Errc::InvalidArgument, "{} must not be NULL", fieldName);
  auto const range = ranges::make_subrange(tab, tab + size);
  for (auto const& e : range)
    if (e == nullptr)
      throw formatEx(Tanker::Errors::Errc::InvalidArgument, "{} elements must not be NULL", fieldName);
  return range | ranges::to<std::vector<T>>;
}
