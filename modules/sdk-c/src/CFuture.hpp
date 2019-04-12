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

inline void* translateExceptions(tc::future<void*> f)
{
  using namespace Tanker;

  try
  {
    return f.get();
  }
  catch (Crypto::InvalidKeySize const& e)
  {
    throw Error::InvalidArgument(e.what());
  }
  catch (cppcodec::parse_error const& e)
  {
    throw Error::formatEx<Error::InvalidArgument>(fmt("invalid base64: {:s}"),
                                                  e.what());
  }
  catch (cppcodec::invalid_output_length const& e)
  {
    throw Error::formatEx<Error::InvalidArgument>(
        fmt("invalid base64 length: {:s}"), e.what());
  }
}

template <template <class> typename Future>
tanker_future_t* makeFuture(Future<void*> fut)
{
  return new tanker_future{
      tc::future<void*>{
          fut.then(tc::get_synchronous_executor(), translateExceptions)},
      nullptr};
}

template <template <class> typename Future>
tanker_future_t* makeFuture(Future<void> fut)
{
  return new tanker_future{
      tc::future<void*>{
          fut.and_then(tc::get_synchronous_executor(),
                       [](auto&&) { return static_cast<void*>(nullptr); })
              .then(tc::get_synchronous_executor(), translateExceptions)},
      nullptr};
}
