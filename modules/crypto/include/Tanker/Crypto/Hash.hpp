#pragma once

#include <Tanker/Crypto/BasicHash.hpp>

namespace Tanker
{
namespace Crypto
{
using Hash = BasicHash<void>;

template <typename T>
bool operator==(BasicHash<void> const& lhs, BasicHash<T> const& rhs) noexcept
{
  return lhs.base() == rhs.base();
}

template <typename T>
bool operator==(BasicHash<T> const& lhs, BasicHash<void> const& rhs) noexcept
{
  return rhs == lhs;
}

template <typename T>
bool operator!=(BasicHash<void> const& lhs, BasicHash<T> const& rhs) noexcept
{
  return !(lhs == rhs);
}

template <typename T>
bool operator!=(BasicHash<T> const& lhs, BasicHash<void> const& rhs) noexcept
{
  return !(lhs == rhs);
}
}
}
