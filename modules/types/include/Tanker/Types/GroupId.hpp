#pragma once

#include <Tanker/Crypto/IsCryptographicType.hpp>
#include <Tanker/Crypto/Types.hpp>

#include <cstddef>
#include <type_traits>

namespace Tanker
{
class GroupId : private Tanker::Crypto::PublicSignatureKey
{
private:
  using base_t = Crypto::PublicSignatureKey;

public:
  using base_t::AsymmetricKey;
  // workaround MSVC bug on: using base_t::array_t
  using array_t = std::array<std::uint8_t, base_t::arraySize>;

  using base_t::operator=;

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
  using base_t::base;

  using base_t::at;
  using base_t::back;
  using base_t::begin;
  using base_t::cbegin;
  using base_t::cend;
  using base_t::crbegin;
  using base_t::crend;
  using base_t::end;
  using base_t::front;
  using base_t::rbegin;
  using base_t::rend;
  using base_t::operator[];
  using base_t::data;
  using base_t::empty;
  using base_t::fill;
  using base_t::size;
  using base_t::swap;

  friend bool operator<(GroupId const& lhs, GroupId const& rhs) noexcept
  {
    return lhs.base() < rhs.base();
  }

  friend bool operator>(GroupId const& lhs, GroupId const& rhs) noexcept
  {
    return lhs.base() > rhs.base();
  }

  friend bool operator>=(GroupId const& lhs, GroupId const& rhs) noexcept
  {
    return lhs.base() >= rhs.base();
  }

  friend bool operator<=(GroupId const& lhs, GroupId const& rhs) noexcept
  {
    return lhs.base() <= rhs.base();
  }

  friend bool operator==(GroupId const& lhs, GroupId const& rhs) noexcept
  {
    return lhs.base() == rhs.base();
  }

  friend bool operator!=(GroupId const& lhs, GroupId const& rhs) noexcept
  {
    return !(lhs.base() == rhs.base());
  }
};

namespace Crypto
{
template <>
struct IsCryptographicType<::Tanker::GroupId> : std::true_type
{
};
}
}

namespace std
{
template <>
class tuple_size<::Tanker::GroupId>
  : public tuple_size<typename ::Tanker::GroupId::array_t>
{
};

template <std::size_t I>
class tuple_element<I, ::Tanker::GroupId>
  : public tuple_element<I, typename ::Tanker::GroupId::array_t>
{
};
}
