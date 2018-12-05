#pragma once

#include <vector>

namespace Tanker
{
template <typename T>
struct BasicPullResult
{
  std::vector<T> found;
  std::vector<decltype(T::id)> notFound;
};
}
