#pragma once

#include <utility>

namespace Tanker
{
namespace Format
{
constexpr std::pair<int, int> parseWidth(char const* it)
{
  int width = 0;

  auto const begin = it;
  while (*it >= '0' && *it <= '9')
  {
    width = width * 10 + static_cast<int>(*it - '0');
    ++it;
  }
  return {width, it - begin};
}
}
}
