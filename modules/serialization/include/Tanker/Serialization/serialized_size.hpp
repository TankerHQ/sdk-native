#pragma once

#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Serialization/detail/static_const.hpp>

#include <mpark/variant.hpp>
#include <optional.hpp>

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
template <typename... Args>
std::size_t serialized_size(mpark::variant<Args...> const& val)
{
  return mpark::visit([](auto const& a) { return serialized_size(a); }, val);
}

template <typename T>
std::size_t serialized_size(std::vector<T> const& vals)
{
  return std::accumulate(vals.begin(),
                         vals.end(),
                         varint_size(vals.size()),
                         [](std::size_t acc, auto const& val) {
                           return acc + serialized_size(val);
                         });
}

template <typename K, typename V>
std::size_t serialized_size(std::map<K, V> const& vals)
{
  return std::accumulate(vals.begin(),
                         vals.end(),
                         varint_size(vals.size()),
                         [](std::size_t acc, auto const& p) {
                           return acc + serialized_size(p.first) +
                                  serialized_size(p.second);
                         });
}

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
constexpr std::size_t serialized_size(T const& number)
{
  return sizeof(number);
}

template <typename T>
std::size_t serialized_size(nonstd::optional<T> const& opt)
{
  if (!opt)
    return 0;
  return serialized_size(*opt);
}

struct serialized_size_fn
{
  template <typename T>
  constexpr std::size_t operator()(T&& val) const
      noexcept(noexcept(serialized_size(std::forward<T>(val))))
  {
    return serialized_size(std::forward<T>(val));
  }
};
}

namespace
{
constexpr auto const& serialized_size =
    detail::static_const<detail::serialized_size_fn>::value;
}
}
}
