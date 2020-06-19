#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>

#include <gsl/gsl-lite.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace Tanker
{
namespace Crypto
{
template <typename T, std::size_t Size>
class BasicCryptographicType : private std::array<std::uint8_t, Size>
{
public:
  using base_t = BasicCryptographicType;
  using array_t = std::array<std::uint8_t, Size>;

  static constexpr auto const arraySize = Size;

  BasicCryptographicType() = default;
  explicit BasicCryptographicType(gsl::span<std::uint8_t const> data);

  template <typename InputIterator, typename Sentinel>
  BasicCryptographicType(InputIterator begin, Sentinel end);

  array_t& base() & noexcept;
  array_t const& base() const& noexcept;
  array_t&& base() && noexcept;
  array_t const&& base() const&& noexcept;

  using typename array_t::const_iterator;
  using typename array_t::const_pointer;
  using typename array_t::const_reference;
  using typename array_t::const_reverse_iterator;
  using typename array_t::difference_type;
  using typename array_t::iterator;
  using typename array_t::pointer;
  using typename array_t::reference;
  using typename array_t::reverse_iterator;
  using typename array_t::size_type;
  using typename array_t::value_type;

  using array_t::at;
  using array_t::back;
  using array_t::begin;
  using array_t::cbegin;
  using array_t::cend;
  using array_t::crbegin;
  using array_t::crend;
  using array_t::end;
  using array_t::front;
  using array_t::rbegin;
  using array_t::rend;
  using array_t::operator[];
  using array_t::data;
  using array_t::empty;
  using array_t::fill;
  using array_t::size;
  using array_t::swap;

  bool is_null() const noexcept;
};

template <typename T, std::size_t S>
struct IsCryptographicType<BasicCryptographicType<T, S>> : std::true_type
{
};

template <typename T>
struct IsCryptographicType<
    T,
    std::enable_if_t<std::is_base_of<typename T::base_t, T>::value &&
                     IsCryptographicType<typename T::base_t>::value>>
  : std::true_type
{
};

template <typename T, std::size_t S>
bool operator<(BasicCryptographicType<T, S> const& lhs,
               BasicCryptographicType<T, S> const& rhs) noexcept;

template <typename T, std::size_t S>
bool operator>(BasicCryptographicType<T, S> const& lhs,
               BasicCryptographicType<T, S> const& rhs) noexcept;

template <typename T, std::size_t S>
bool operator<=(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept;

template <typename T, std::size_t S>
bool operator>=(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept;

template <typename T, std::size_t S>
bool operator==(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept;

template <typename T, std::size_t S>
bool operator!=(BasicCryptographicType<T, S> const& lhs,
                BasicCryptographicType<T, S> const& rhs) noexcept;
}
}

// Required for cppcodec array-like types support
namespace std
{
template <typename T, std::size_t S>
class tuple_size<::Tanker::Crypto::BasicCryptographicType<T, S>>
  : public tuple_size<
        typename ::Tanker::Crypto::BasicCryptographicType<T, S>::array_t>
{
};

template <std::size_t I, typename T, std::size_t S>
class tuple_element<I, ::Tanker::Crypto::BasicCryptographicType<T, S>>
  : public tuple_element<
        I,
        typename ::Tanker::Crypto::BasicCryptographicType<T, S>::array_t>
{
};
}

#define TANKER_CRYPTO_INCLUDED_BY_BASIC_CRYPTOGRAPHIC_TYPE
#include <Tanker/Crypto/detail/BasicCryptographicTypeImpl.hpp>
#undef TANKER_CRYPTO_INCLUDED_BY_BASIC_CRYPTOGRAPHIC_TYPE
