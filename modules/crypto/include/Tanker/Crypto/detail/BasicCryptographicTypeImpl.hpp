#pragma once

#ifndef TANKER_CRYPTO_INCLUDED_BY_BASIC_CRYPTOGRAPHIC_TYPE
#error \
    "Thou shall not include this file directly, include Tanker/Crypto/BasicCryptographicType.hpp instead!"
#endif

#include <Tanker/Crypto/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <mgs/codecs/concepts/input_source.hpp>
#include <mgs/codecs/iterator_sentinel_source.hpp>
#include <mgs/meta/concepts/input_iterator.hpp>
#include <mgs/meta/concepts/output_iterator.hpp>
#include <mgs/meta/concepts/sentinel_for.hpp>
#include <mgs/ssize_t.hpp>

#include <algorithm>
#include <iterator>
#include <string>
#include <typeinfo>

namespace Tanker
{
namespace Crypto
{
namespace detail
{
template <typename IS, typename O>
std::pair<O, mgs::ssize_t> read_at_most(
    mgs::codecs::input_source<IS, O>& is,
    mgs::meta::output_iterator<O, typename IS::element_type> o,
    mgs::ssize_t n)
{
  auto total_read = static_cast<mgs::ssize_t>(0);
  while (n != 0)
  {
    auto const res = is.read(o, n);
    o = res.first;
    if (res.second == 0)
      break;
    total_read += res.second;
    n -= res.second;
  }
  return {o, total_read};
}
}

template <typename T, std::size_t S>
BasicCryptographicType<T, S>::BasicCryptographicType(
    gsl::span<std::uint8_t const> data)
  : BasicCryptographicType(data.begin(), data.end())
{
}

template <typename T, std::size_t S>
template <typename InputIterator, typename Sentinel>
BasicCryptographicType<T, S>::BasicCryptographicType(
    mgs::meta::input_iterator<InputIterator> begin,
    mgs::meta::sentinel_for<Sentinel, InputIterator> end)
{
  auto is = mgs::codecs::make_iterator_sentinel_source(begin, end);
  auto const [it, total_read] = detail::read_at_most(is, this->data(), S);
  if (total_read < static_cast<mgs::ssize_t>(S))
  {
    throw Errors::formatEx(
        Errc::InvalidBufferSize,
        FMT_STRING("invalid size for {:s}: got {:d}, expected {:d}"),
        typeid(T).name(),
        total_read,
        this->size());
  }
  // make sure there is no additional data
  if (detail::read_at_most(is, this->data(), 1).second != 0)
  {
    throw Errors::formatEx(
        Errc::InvalidBufferSize,
        FMT_STRING("invalid size for {:s}: larger than expected {:d}"),
        typeid(T).name(),
        this->size());
  }
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
    auto BasicCryptographicType<T, S>::base() const &&
    noexcept -> array_t const&&
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
