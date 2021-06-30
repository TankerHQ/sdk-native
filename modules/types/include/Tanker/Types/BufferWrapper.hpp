#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include <mgs/base64.hpp>

namespace Tanker
{
template <typename>
class BufferWrapper : std::vector<std::uint8_t>
{
public:
  using base_t = std::vector<std::uint8_t>;

  BufferWrapper() = default;

  template <typename InputIterator>
  BufferWrapper(InputIterator begin, InputIterator end) : base_t(begin, end)
  {
  }

  BufferWrapper(base_t::size_type count, std::uint8_t value = 0)
    : base_t(count, value)
  {
  }

  explicit BufferWrapper(base_t const& s) : base_t(s)
  {
  }

  explicit BufferWrapper(base_t&& s) : base_t(std::move(s))
  {
  }

  base_t const& vector() const noexcept
  {
    return *this;
  }

  void swap(BufferWrapper& other) noexcept(
      noexcept(std::declval<base_t&>().swap(other)))
  {
    this->base_t::swap(other);
  }

  // std::vector interface

  // Member types
  using base_t::allocator_type;
  using base_t::const_iterator;
  using base_t::const_pointer;
  using base_t::const_reference;
  using base_t::const_reverse_iterator;
  using base_t::difference_type;
  using base_t::iterator;
  using base_t::pointer;
  using base_t::reference;
  using base_t::reverse_iterator;
  using base_t::size_type;
  using base_t::value_type;

  // Element access
  using base_t::at;
  using base_t::operator[];
  using base_t::back;
  using base_t::data;
  using base_t::front;

  // Iterators
  using base_t::begin;
  using base_t::cbegin;
  using base_t::crbegin;
  using base_t::rbegin;

  using base_t::cend;
  using base_t::crend;
  using base_t::end;
  using base_t::rend;

  // Capacity
  using base_t::capacity;
  using base_t::empty;
  using base_t::max_size;
  using base_t::reserve;
  using base_t::shrink_to_fit;
  using base_t::size;

  // Operations
  using base_t::clear;
  using base_t::erase;
  using base_t::insert;
  using base_t::pop_back;
  using base_t::push_back;
  using base_t::resize;
};

template <typename T>
bool operator==(BufferWrapper<T> const& lhs,
                BufferWrapper<T> const& rhs) noexcept
{
  return lhs.vector() == rhs.vector();
}

template <typename T>
bool operator!=(BufferWrapper<T> const& lhs,
                BufferWrapper<T> const& rhs) noexcept
{
  return !(lhs == rhs);
}

template <typename T>
bool operator<(BufferWrapper<T> const& lhs,
               BufferWrapper<T> const& rhs) noexcept
{
  return lhs.vector() < rhs.vector();
}

template <typename T>
bool operator>(BufferWrapper<T> const& lhs,
               BufferWrapper<T> const& rhs) noexcept
{
  return lhs.vector() > rhs.vector();
}

template <typename T>
bool operator>=(BufferWrapper<T> const& lhs,
                BufferWrapper<T> const& rhs) noexcept
{
  return lhs.vector() >= rhs.vector();
}

template <typename T>
bool operator<=(BufferWrapper<T> const& lhs,
                BufferWrapper<T> const& rhs) noexcept
{
  return lhs.vector() <= rhs.vector();
}

// those methods are templates, to avoid including json.hpp
template <typename BasicJsonType, typename T>
void from_json(BasicJsonType const& j, BufferWrapper<T>& b)
{
  b = BufferWrapper<T>{mgs::base64::decode(j.template get<std::string>())};
}

template <typename BasicJsonType, typename T>
void to_json(BasicJsonType& j, BufferWrapper<T> const& b)
{
  j = mgs::base64::encode(b.vector());
}
}

namespace std
{
template <typename T>
struct hash<Tanker::BufferWrapper<T>>
{
  size_t operator()(Tanker::BufferWrapper<T> const& b) const
  {
    std::string s(b.vector().begin(), b.vector().end());
    return hash<std::string>()(s);
  }
};

template <typename T>
void swap(Tanker::BufferWrapper<T>& lhs,
          Tanker::BufferWrapper<T>& rhs) noexcept(noexcept(lhs.swap(rhs)))
{
  lhs.swap(rhs);
}
}
