#pragma once

#include <iosfwd>
#include <string>

#include <fmt/core.h>
#include <fmt/format.h>

namespace Tanker
{

template <typename>
class StringWrapper : std::string
{
public:
  using base_t = std::string;

  StringWrapper() = default;

  template <typename InputIterator>
  StringWrapper(InputIterator begin, InputIterator end) : base_t(begin, end)
  {
  }

  StringWrapper(base_t::value_type const* s, std::size_t size) : base_t(s, size)
  {
  }

  explicit StringWrapper(base_t const& s) : base_t(s)
  {
  }

  explicit StringWrapper(base_t&& s) : base_t(std::move(s))
  {
  }

  base_t const& string() const noexcept
  {
    return *this;
  }

  void swap(StringWrapper& other) noexcept(
      noexcept(std::declval<base_t&>().swap(other)))
  {
    this->base_t::swap(other);
  }

  // std::string interface

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
  using base_t::traits_type;
  using base_t::value_type;

  // Element access
  using base_t::at;
  using base_t::operator[];
  using base_t::back;
  using base_t::c_str;
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
  using base_t::length;
  using base_t::max_size;
  using base_t::reserve;
  using base_t::shrink_to_fit;
  using base_t::size;

  // Operations
  using base_t::append;
  using base_t::clear;
  using base_t::erase;
  using base_t::insert;
  using base_t::pop_back;
  using base_t::push_back;
  using base_t::operator+=;
  using base_t::compare;
  using base_t::copy;
  using base_t::replace;
  using base_t::resize;
  using base_t::substr;

  // Search
  using base_t::find;
  using base_t::find_first_not_of;
  using base_t::find_first_of;
  using base_t::find_last_not_of;
  using base_t::find_last_of;
  using base_t::rfind;
};

template <typename T>
bool operator==(StringWrapper<T> const& lhs,
                StringWrapper<T> const& rhs) noexcept
{
  return lhs.string() == rhs.string();
}

template <typename T>
bool operator!=(StringWrapper<T> const& lhs,
                StringWrapper<T> const& rhs) noexcept
{
  return !(lhs == rhs);
}

template <typename T>
bool operator<(StringWrapper<T> const& lhs,
               StringWrapper<T> const& rhs) noexcept
{
  return lhs.string() < rhs.string();
}

template <typename T>
bool operator>(StringWrapper<T> const& lhs,
               StringWrapper<T> const& rhs) noexcept
{
  return lhs.string() > rhs.string();
}

template <typename T>
bool operator>=(StringWrapper<T> const& lhs,
                StringWrapper<T> const& rhs) noexcept
{
  return lhs.string() >= rhs.string();
}

template <typename T>
bool operator<=(StringWrapper<T> const& lhs,
                StringWrapper<T> const& rhs) noexcept
{
  return lhs.string() <= rhs.string();
}

template <typename T>
std::ostream& operator<<(std::ostream& os, StringWrapper<T> const& s)
{
  return os << s.string();
}

template <typename T>
std::istream& operator>>(std::istream& os, StringWrapper<T>& s)
{
  std::string str;
  os >> str;
  s = StringWrapper<T>{std::move(str)};
  return os;
}

// those methods are templates, to avoid including json.hpp
template <typename BasicJsonType, typename T>
void from_json(BasicJsonType const& j, StringWrapper<T>& s)
{
  s = StringWrapper<T>{j.template get<std::string>()};
}

template <typename BasicJsonType, typename T>
void to_json(BasicJsonType& j, StringWrapper<T> const& s)
{
  j = s.string();
}

template <typename T>
fmt::string_view to_string_view(StringWrapper<T> const& val)
{
  return fmt::string_view(val.string());
}
}

namespace fmt
{
template <typename Tag>
struct formatter<Tanker::StringWrapper<Tag>, char>
  : formatter<fmt::basic_string_view<char>, char>
{
  template <typename FormatContext>
  auto format(Tanker::StringWrapper<Tag> const& str, FormatContext& ctx)
  {
    return formatter<fmt::basic_string_view<char>, char>::format(
        to_string_view(str), ctx);
  }
};
}

namespace std
{
template <typename T>
struct hash<Tanker::StringWrapper<T>>
{
  size_t operator()(Tanker::StringWrapper<T> const& s) const
  {
    return hash<std::string>()(s.string());
  }
};

template <typename T>
void swap(Tanker::StringWrapper<T>& lhs,
          Tanker::StringWrapper<T>& rhs) noexcept(noexcept(lhs.swap(rhs)))
{
  lhs.swap(rhs);
}
}
