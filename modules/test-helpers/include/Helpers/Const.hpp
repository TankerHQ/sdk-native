#pragma once

#include <type_traits>

namespace Tanker
{
// only allow const values to be passed
// using T const& would bind non-const lvalues and rvalues as well
// also, std::is_const_v<T> will be false for all values if T const& is used
template <typename T,
          typename = std::enable_if_t<
              std::is_const<std::remove_reference_t<T>>::value>>
std::remove_const_t<T>& unconstify(T& t)
{
  return const_cast<std::remove_const_t<T>&>(t);
}
}
