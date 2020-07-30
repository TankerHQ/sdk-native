#pragma once

#include <tconcurrent/coroutine.hpp>

namespace test_helpers_detail
{
template <typename T>
struct cotask_type
{
  using type = tc::cotask<typename T::value_type>;
};
}

#define AWAIT_VOID(code) \
  tc::async_resumable([&]() -> tc::cotask<void> { TC_AWAIT(code); }).get()

#define AWAIT(code)                                                       \
  tc::async_resumable([&]() -> typename test_helpers_detail::cotask_type< \
                                decltype(code)>::type {                   \
    TC_RETURN(TC_AWAIT(code));                                            \
  }).get()

#define WRAP_COTASK(...) \
  ([&]() -> tc::cotask<decltype(__VA_ARGS__)> { TC_RETURN((__VA_ARGS__)); }())
