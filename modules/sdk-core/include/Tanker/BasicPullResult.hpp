#pragma once

#include <vector>

namespace Tanker
{
template <typename T, typename Id = decltype(T::id)>
struct BasicPullResult
{
  std::vector<T> found;
  std::vector<Id> notFound;
};
}
