#pragma once

#include <Tanker/Crypto/InvalidKeySize.hpp>

#include <gsl-lite.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <string>

#define TANKER_CRYPTO_CRYPTOGRAPHIC_TYPE_IMPL(Self, ArraySize, Name)         \
                                                                             \
public:                                                                      \
  using array_t = std::array<std::uint8_t, ArraySize>;                       \
                                                                             \
  static constexpr auto arraySize = ArraySize;                               \
  static constexpr char const* name = #Name;                                 \
                                                                             \
  Self() = default;                                                          \
                                                                             \
  explicit Self(gsl::span<std::uint8_t const> data)                          \
    : Self(data.begin(), data.end())                                         \
  {                                                                          \
  }                                                                          \
                                                                             \
  template <typename InputIterator>                                          \
  Self(InputIterator begin, InputIterator end)                               \
  {                                                                          \
    auto const dist = static_cast<size_type>(std::distance(begin, end));     \
    if (dist != this->size())                                                \
    {                                                                        \
      throw ::Tanker::Crypto::InvalidKeySize(                                \
          "invalid size for " #Name ": got " + std::to_string(dist) +        \
          ", expected " + std::to_string(this->size()));                     \
    }                                                                        \
    std::copy(begin, end, this->data());                                     \
  }                                                                          \
                                                                             \
  Self& operator=(gsl::span<std::uint8_t const> data)                        \
  {                                                                          \
    if (data.size() != this->size())                                         \
    {                                                                        \
      throw ::Tanker::Crypto::InvalidKeySize(                                \
          "invalid size for " #Name ": got " + std::to_string(data.size()) + \
          ", expected " + std::to_string(this->size()));                     \
    }                                                                        \
    std::copy(data.begin(), data.end(), this->data());                       \
    return *static_cast<Self*>(this);                                        \
  }                                                                          \
                                                                             \
  ~Self() = default;                                                         \
                                                                             \
  array_t& base() & noexcept                                                 \
  {                                                                          \
    return *static_cast<array_t*>(this);                                     \
  }                                                                          \
                                                                             \
  array_t const& base() const& noexcept                                      \
  {                                                                          \
    return *static_cast<array_t const*>(this);                               \
  }                                                                          \
                                                                             \
  array_t&& base() && noexcept                                               \
  {                                                                          \
    return std::move(*static_cast<array_t*>(this));                          \
  }                                                                          \
                                                                             \
  array_t const&& base() const&& noexcept                                    \
  {                                                                          \
    return std::move(*static_cast<array_t const*>(this));                    \
  }                                                                          \
                                                                             \
  using array_t::value_type;                                                 \
  using array_t::size_type;                                                  \
  using array_t::difference_type;                                            \
  using array_t::reference;                                                  \
  using array_t::const_reference;                                            \
  using array_t::pointer;                                                    \
  using array_t::const_pointer;                                              \
  using array_t::iterator;                                                   \
  using array_t::const_iterator;                                             \
  using array_t::reverse_iterator;                                           \
  using array_t::const_reverse_iterator;                                     \
                                                                             \
  using array_t::begin;                                                      \
  using array_t::end;                                                        \
  using array_t::cbegin;                                                     \
  using array_t::cend;                                                       \
  using array_t::rbegin;                                                     \
  using array_t::rend;                                                       \
  using array_t::crbegin;                                                    \
  using array_t::crend;                                                      \
  using array_t::at;                                                         \
  using array_t::front;                                                      \
  using array_t::back;                                                       \
  using array_t::operator[];                                                 \
  using array_t::size;                                                       \
  using array_t::empty;                                                      \
  using array_t::data;                                                       \
  using array_t::fill;                                                       \
  using array_t::swap;                                                       \
                                                                             \
  bool is_null() const                                                       \
  {                                                                          \
    return std::all_of(begin(), end(), [](auto c) { return c == 0; });       \
  }                                                                          \
                                                                             \
  friend bool operator<(Self const& lhs, Self const& rhs) noexcept           \
  {                                                                          \
    return lhs.base() < rhs.base();                                          \
  }                                                                          \
                                                                             \
  friend bool operator>(Self const& lhs, Self const& rhs) noexcept           \
  {                                                                          \
    return lhs.base() > rhs.base();                                          \
  }                                                                          \
                                                                             \
  friend bool operator>=(Self const& lhs, Self const& rhs) noexcept          \
  {                                                                          \
    return lhs.base() >= rhs.base();                                         \
  }                                                                          \
                                                                             \
  friend bool operator<=(Self const& lhs, Self const& rhs) noexcept          \
  {                                                                          \
    return lhs.base() <= rhs.base();                                         \
  }                                                                          \
                                                                             \
  friend bool operator==(Self const& lhs, Self const& rhs) noexcept          \
  {                                                                          \
    return lhs.base() == rhs.base();                                         \
  }                                                                          \
                                                                             \
  friend bool operator!=(Self const& lhs, Self const& rhs) noexcept          \
  {                                                                          \
    return !(lhs == rhs);                                                    \
  }
