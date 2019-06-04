#pragma once

#include <Tanker/Error.hpp>

#include <Tanker/Crypto/InvalidKeySize.hpp>

#include <ctanker/async.h>

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

template <template <typename> class Future>
tanker_future_t* makeFuture(Future<void*> fut)
{
  return new tanker_future{std::move(fut), nullptr};
}

template <template <typename> class Future>
tanker_future_t* makeFuture(Future<void> fut)
{
  return new tanker_future{
      fut.and_then(tc::get_synchronous_executor(),
                   [](auto&&) { return static_cast<void*>(nullptr); }),
      nullptr};
}
