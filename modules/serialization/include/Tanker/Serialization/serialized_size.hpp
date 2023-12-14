#pragma once

#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Serialization/detail/static_const.hpp>

#include <boost/variant2/variant.hpp>
#include <optional>

#include <cstddef>
#include <map>
#include <numeric>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Serialization
{
namespace detail
{
template <typename T, typename U>
std::size_t serialized_size(std::pair<T, U> const& val)
{
  return serialized_size(val.first) + serialized_size(val.second);
}

template <typename... Args>
std::size_t serialized_size(boost::variant2::variant<Args...> const& val)
{
  return boost::variant2::visit([](auto const& a) { return serialized_size(a); }, val);
}

template <typename T>
std::size_t serialized_size(std::vector<T> const& vals)
{
  return std::accumulate(vals.begin(), vals.end(), varint_size(vals.size()), [](std::size_t acc, auto const& val) {
    return acc + serialized_size(val);
  });
}

template <typename K, typename V>
std::size_t serialized_size(std::map<K, V> const& vals)
{
  return std::accumulate(vals.begin(), vals.end(), varint_size(vals.size()), [](std::size_t acc, auto const& p) {
    return acc + serialized_size(p.first) + serialized_size(p.second);
  });
}

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
constexpr std::size_t serialized_size(T const& number)
{
  return sizeof(number);
}

template <typename T>
std::size_t serialized_size(std::optional<T> const& opt)
{
  if (!opt)
    return 0;
  return serialized_size(*opt);
}

struct serialized_size_fn
{
  template <typename T>
  constexpr std::size_t operator()(T&& val) const noexcept(noexcept(serialized_size(std::forward<T>(val))))
  {
    return serialized_size(std::forward<T>(val));
  }
};
}

namespace
{
constexpr auto const& serialized_size = detail::static_const<detail::serialized_size_fn>::value;
}
}
}
