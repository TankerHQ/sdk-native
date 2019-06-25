#pragma once

#ifndef TANKER_CRYPTO_INCLUDED_BY_BASIC_CRYPTOGRAPHIC_TYPE
#error \
    "Thou shall not include this file directly, include Tanker/Crypto/BasicCryptographicType.hpp instead!"
#endif

#include <Tanker/Crypto/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>

#include <algorithm>
#include <iterator>
#include <string>
#include <typeinfo>

namespace Tanker
{
namespace Crypto
{
template <typename T, std::size_t S>
BasicCryptographicType<T, S>::BasicCryptographicType(
    gsl::span<std::uint8_t const> data)
  : BasicCryptographicType(data.begin(), data.end())
{
}

template <typename T, std::size_t S>
template <typename InputIterator, typename Sentinel>
BasicCryptographicType<T, S>::BasicCryptographicType(InputIterator begin,
                                                     Sentinel end)
{
  auto const dist =
      static_cast<BasicCryptographicType::size_type>(std::distance(begin, end));
  if (dist != this->size())
  {
    throw Errors::formatEx(
        Errc::InvalidBufferSize,
        TFMT("invalid size for {:s}: got {:d}, expected {:d}"),
        typeid(T).name(),
        dist,
        this->size());
  }
  std::copy(begin, end, this->data());
}

template <typename T, std::size_t S>
auto BasicCryptographicType<T, S>::base() & noexcept -> array_t&
{
  return *static_cast<array_t*>(this);
}

template <typename T, std::size_t S>
auto BasicCryptographicType<T, S>::base() const & noexcept -> array_t const&
{
  return *static_cast<array_t const*>(this);
}

template <typename T, std::size_t S>
auto BasicCryptographicType<T, S>::base() && noexcept -> array_t&&
{
  return std::move(*static_cast<array_t*>(this));
}

template <typename T, std::size_t S>
auto BasicCryptographicType<T, S>::base() const && noexcept -> array_t const&&
{
  return std::move(*static_cast<array_t const*>(this));
}

template <typename T, std::size_t S>
bool BasicCryptographicType<T, S>::is_null() const noexcept
{
  return std::all_of(begin(), end(), [](auto c) { return c == 0; });
}

template <typename T, std::size_t S>
bool operator<(BasicCryptographicType<T, S> const& lhs,
               BasicCryptographicType<T, S> const& rhs) noexcept
{
  return lhs.base() < rhs.base();
}

template <typename T, std::size_t S>
bool operator>(BasicCryptographicType<T, S> const& lhs,
               BasicCryptographicType<T, S> const& rhs) noexcept
{
  return lhs.base() > rhs.base();
}

template <typename T, std::size_t S>
bool operator<=(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept
{
  return lhs.base() <= rhs.base();
}

template <typename T, std::size_t S>
bool operator>=(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept
{
  return lhs.base() >= rhs.base();
}

template <typename T, std::size_t S>
bool operator==(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept
{
  return lhs.base() == rhs.base();
}

template <typename T, std::size_t S>
bool operator!=(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept
{
  return !(lhs == rhs);
}
}
}
