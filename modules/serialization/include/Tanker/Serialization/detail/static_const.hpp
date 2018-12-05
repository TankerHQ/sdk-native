#pragma once

namespace Tanker
{
namespace Serialization
{
namespace detail
{
template <typename T>
struct static_const
{
  static constexpr T value{};
};

template <typename T>
constexpr T static_const<T>::value;
}
}
}
