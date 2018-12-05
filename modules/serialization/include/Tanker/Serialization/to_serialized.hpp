#pragma once

#include <iterator>
#include <map>
#include <type_traits>
#include <vector>

#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Serialization/detail/static_const.hpp>

#include <mpark/variant.hpp>
#include <optional.hpp>

namespace Tanker
{
namespace Serialization
{
namespace detail
{
template <typename OutputIterator, typename T>
void to_serialized(OutputIterator it, std::vector<T> const& vals)
{
  varint_write(it, vals.size());
  for (auto const& val : vals)
    to_serialized(it, val);
}

template <typename OutputIterator, typename K, typename V>
void to_serialized(OutputIterator it, std::map<K, V> const& vals)
{
  varint_write(it, vals.size());
  for (auto const& p : vals)
  {
    to_serialized(it, p.first);
    to_serialized(it, p.second);
  }
}

template <typename OutputIterator, typename T>
void to_serialized(OutputIterator it, nonstd::optional<T> const& opt)
{
  if (opt)
    to_serialized(it, *opt);
}

template <typename OutputIterator, typename ...Args>
void to_serialized(OutputIterator it, mpark::variant<Args...> const& v)
{
  mpark::visit([it](auto const& a) { to_serialized(it, a); }, v);
}

struct to_serialized_fn
{
  template <typename OutputIterator, typename T>
  void operator()(OutputIterator it, T const& val) const
      noexcept(noexcept(to_serialized(it, val)))
  {
    return to_serialized(it, val);
  }
};
}

namespace
{
constexpr auto const& to_serialized =
    detail::static_const<detail::to_serialized_fn>::value;
}
}
}
