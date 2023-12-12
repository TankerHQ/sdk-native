#pragma once

#include <iterator>
#include <map>
#include <stdexcept>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Serialization/detail/static_const.hpp>

// For more info:
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2015/n4381.html

namespace Tanker
{
namespace Serialization
{
namespace detail
{
template <typename T>
T deserialize_impl(SerializedSource&);

template <typename T>
void deserialize_impl(SerializedSource&, T&);

template <typename T, typename U>
void from_serialized(SerializedSource& ss, std::pair<T, U>& vals)
{
  deserialize_impl(ss, vals.first);
  deserialize_impl(ss, vals.second);
}

template <typename T>
void from_serialized(SerializedSource& ss, std::vector<T>& vals)
{
  auto const nbVals = ss.read_varint();
  vals.reserve(nbVals);

  for (std::size_t i = 0; i < nbVals; ++i)
    vals.push_back(deserialize_impl<T>(ss));
}

template <typename K, typename V>
void from_serialized(SerializedSource& ss, std::map<K, V>& m)
{
  auto const nbVals = ss.read_varint();
  for (std::size_t i = 0; i < nbVals; ++i)
  {
    auto key = deserialize_impl<K>(ss);
    m[std::move(key)] = deserialize_impl<V>(ss);
  }
}

template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
void from_serialized(SerializedSource& ss, T& number)
{
  auto const buffer = ss.read(sizeof(T));
  std::copy(buffer.begin(), buffer.end(), reinterpret_cast<char*>(&number));
}

template <typename T>
T deserialize_impl(SerializedSource& ss)
{
  T ret;
  deserialize_impl(ss, ret);
  return ret;
}

template <typename T>
void deserialize_impl(SerializedSource& ss, T& val)
{
  from_serialized(ss, val);
}

struct from_serialized_fn
{
  template <typename T>
  void operator()(SerializedSource& ss, T& val) const noexcept(noexcept(from_serialized(ss, val)))
  {
    return from_serialized(ss, val);
  }
};
}

namespace
{
constexpr auto const& from_serialized = detail::static_const<detail::from_serialized_fn>::value;
}
}
}
