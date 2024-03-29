#pragma once

#include <ctanker/async.h>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>

#include <tconcurrent/future.hpp>

#include <cstdlib>
#include <cstring>
#include <memory>

struct tanker_error_deleter
{
  void operator()(tanker_error_t* err)
  {
    free(const_cast<char*>(err->message));
    delete err;
  }
};

struct tanker_future
{
  tc::future<void*> future;
  std::unique_ptr<tanker_error_t, tanker_error_deleter> error;
};

inline tanker_future_t* makeFuture(tc::shared_future<void*> fut)
{
  return new tanker_future{fut.and_then([](void* arg) { return arg; }), nullptr};
}

inline tanker_future_t* makeFuture(tc::future<void*> fut)
{
  return new tanker_future{std::move(fut), nullptr};
}

template <template <typename> class Future>
tanker_future_t* makeFuture(Future<void> fut)
{
  return new tanker_future{
      fut.and_then(tc::get_synchronous_executor(), [](auto&&) { return static_cast<void*>(nullptr); }), nullptr};
}
