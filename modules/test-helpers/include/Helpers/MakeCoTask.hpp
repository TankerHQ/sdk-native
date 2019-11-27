#pragma once

#include <tconcurrent/coroutine.hpp>
#include <utility>

namespace Tanker
{
template <typename T>
auto makeCoTask(T value) -> tc::cotask<T>
{
  TC_RETURN(std::move(value));
}
}