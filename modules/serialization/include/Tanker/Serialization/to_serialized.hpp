#pragma once

#include <iterator>
#include <map>
#include <type_traits>
#include <utility>
#include <vector>

#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Serialization/detail/static_const.hpp>

#include <boost/variant2/variant.hpp>
#include <optional>

namespace Tanker
{
namespace Serialization
{
namespace detail
{
template <typename T, typename U>
std::uint8_t* to_serialized(std::uint8_t* it, std::pair<T, U> const& vals)
{
  it = to_serialized(it, vals.first);
  return to_serialized(it, vals.second);
}

template <typename T>
std::uint8_t* to_serialized(std::uint8_t* it, std::vector<T> const& vals)
{
  it = varint_write(it, vals.size());
  for (auto const& val : vals)
    it = to_serialized(it, val);
  return it;
}

template <typename K, typename V>
std::uint8_t* to_serialized(std::uint8_t* it, std::map<K, V> const& vals)
{
  it = varint_write(it, vals.size());
  for (auto const& p : vals)
  {
    it = to_serialized(it, p.first);
    it = to_serialized(it, p.second);
  }
  return it;
}

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
std::uint8_t* to_serialized(std::uint8_t* it, T number)
{
  return std::copy(reinterpret_cast<char const*>(&number), reinterpret_cast<char const*>(&number) + sizeof(number), it);
}

template <typename T>
std::uint8_t* to_serialized(std::uint8_t* it, std::optional<T> const& opt)
{
  if (opt)
    it = to_serialized(it, *opt);
  return it;
}

template <typename... Args>
std::uint8_t* to_serialized(std::uint8_t* it, boost::variant2::variant<Args...> const& v)
{
  return boost::variant2::visit([it](auto const& a) { return to_serialized(it, a); }, v);
}

struct to_serialized_fn
{
  template <typename T>
  std::uint8_t* operator()(std::uint8_t* it, T const& val) const noexcept(noexcept(to_serialized(it, val)))
  {
    return to_serialized(it, val);
  }
};
}

namespace
{
constexpr auto const& to_serialized = detail::static_const<detail::to_serialized_fn>::value;
}
}
}
