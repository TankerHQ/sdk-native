#pragma once

#include <gsl-lite.hpp>

#include <string>
#include <tuple>
#include <vector>

namespace Tanker
{
inline auto make_buffer(std::string const& str)
{
  return std::vector<uint8_t>(std::cbegin(str), std::cend(str));
}

template <typename T>
T make(std::string const& id)
{
  std::vector<uint8_t> v(id.begin(), id.end());
  v.resize(std::tuple_size<T>::value);
  return T(gsl::make_span(v));
}

template <typename T>
T make(std::initializer_list<uint8_t> bytes)
{
  return T(gsl::make_span(bytes.begin(), bytes.end()));
}
}
