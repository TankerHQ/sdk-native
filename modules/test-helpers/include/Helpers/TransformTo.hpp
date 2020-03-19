#pragma once

#include <algorithm>
#include <vector>

namespace Tanker::Test
{

template <typename T, typename SrcIt, typename F>
T transformTo(SrcIt begin, SrcIt end, T init, F&& f)
{
  init.reserve(init.size() + std::distance(begin, end));
  std::transform(begin, end, std::back_inserter(init), std::forward<F>(f));
  return init;
}

template <typename T, typename Src, typename F>
T transformTo(Src const& source, T init, F&& f)
{
  return transformTo<T>(std::begin(source),
                        std::end(source),
                        std::move(init),
                        std::forward<F>(f));
}

template <typename T, typename U, typename F>
T transformTo(U const& source, F&& f)
{
  return transformTo<T>(source, T{}, std::forward<F>(f));
}

template <typename T, typename U>
T transformTo(U const& source)
{
  return transformTo<T>(
      source, [](auto&& item) -> typename T::value_type { return item; });
}
}
