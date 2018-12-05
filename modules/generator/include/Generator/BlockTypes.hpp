#pragma once
#include <Tanker/Types/Password.hpp>

#include <cstdlib>
#include <string>

namespace Tanker
{
namespace Generator
{
enum class Nature
{
  User,
  Device,
  Share,
  Group,
  UnlockPassword,
};

template <typename T, Nature N>
struct Item
{
  static auto const nature = N;
  T const value;
};

template <Nature N>
using Quantity = Item<std::size_t, N>;

inline namespace literals
{
#define LITERAL_QUANTITY(NATURE, NAME)                                     \
  constexpr Quantity<Nature::NATURE> operator"" NAME(unsigned long long q) \
  {                                                                        \
    return Quantity<Nature::NATURE>{static_cast<std::size_t>(q)};          \
  }

LITERAL_QUANTITY(User, _users)
LITERAL_QUANTITY(Device, _devices)
LITERAL_QUANTITY(Share, _shares)
LITERAL_QUANTITY(Group, _groups)

#undef LITERAL_QUANTITY
}

#define DEFINE_QUANTITY(NATURE) using NATURE##Quant = Quantity<Nature::NATURE>;

DEFINE_QUANTITY(User)
DEFINE_QUANTITY(Device)
DEFINE_QUANTITY(Share)
DEFINE_QUANTITY(Group)

#undef DEFINE_QUANTITY

struct UnlockPassword : Item<char const*, Nature::UnlockPassword>
{
  using parent = Item<char const*, Nature::UnlockPassword>;

  UnlockPassword() = default;
  constexpr UnlockPassword(const char* v) noexcept : parent{v}
  {
  }

  operator Password() const
  {
    return Password{value};
  }
};

inline namespace literals
{
constexpr UnlockPassword operator"" _ukp(char const* s, std::size_t)
{
  return UnlockPassword{s};
}
}

template <Nature N>
auto make_quantity(std::size_t q)
{
  return Quantity<N>{q};
}
}
}
