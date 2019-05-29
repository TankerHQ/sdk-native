#include <ctanker/error.h>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>

#include <tconcurrent/promise.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

namespace
{
tanker_promise_t* asCPromise(tc::promise<void*>* prom)
{
  return reinterpret_cast<tanker_promise_t*>(prom);
}

tc::promise<void*>* asCppPromise(tanker_promise_t* prom)
{
  return reinterpret_cast<tc::promise<void*>*>(prom);
}
}

tanker_promise_t* tanker_promise_create(void)
{
  return asCPromise(new tc::promise<void*>());
}

void tanker_promise_destroy(tanker_promise_t* promise)
{
  delete asCppPromise(promise);
}

tanker_future_t* tanker_promise_get_future(tanker_promise_t* promise)
{
  return makeFuture(asCppPromise(promise)->get_future());
}

void tanker_promise_set_value(tanker_promise_t* promise, void* value)
{
  asCppPromise(promise)->set_value(value);
}

void* tanker_future_get_voidptr(tanker_future_t* future)
{
  return future->future.get();
}

unsigned char tanker_future_has_error(tanker_future_t* future)
{
  return future->future.has_exception();
}

#define CHECK_ENUM(cerror, cpperror)                                  \
  static_assert(static_cast<int>(TANKER_ERROR_##cerror) ==            \
                    static_cast<int>(Tanker::Errors::Errc::cpperror), \
                "Error code enums not matching")

CHECK_ENUM(INVALID_ARGUMENT, InvalidArgument);
CHECK_ENUM(INTERNAL_ERROR, InternalError);
CHECK_ENUM(NETWORK_ERROR, NetworkError);
CHECK_ENUM(PRECONDITION_FAILED, PreconditionFailed);
CHECK_ENUM(OPERATION_CANCELED, OperationCanceled);
CHECK_ENUM(OPERATION_FORBIDDEN, OperationForbidden);
CHECK_ENUM(DECRYPTION_FAILED, DecryptionFailed);
CHECK_ENUM(INVALID_GROUP_SIZE, InvalidGroupSize);
CHECK_ENUM(NOT_FOUND, NotFound);
CHECK_ENUM(ALREADY_EXISTS, AlreadyExists);
CHECK_ENUM(INVALID_CREDENTIALS, InvalidCredentials);
CHECK_ENUM(TOO_MANY_ATTEMPTS, TooManyAttempts);
CHECK_ENUM(EXPIRED, Expired);
CHECK_ENUM(DEVICE_REVOKED, DeviceRevoked);

CHECK_ENUM(LAST, Last);

// Hi fellow Tanker developer!
// If you come to this place after being pointed out by your compiler companion
// that the below static_assert failed, it's probably because you forgot to
// update the above assertions. You must add the appropriate CHECK_ENUM()'s.
// Solely then you can fix the static_assert() to allow you and your fellowship
// to continue their journey.
static_assert(TANKER_ERROR_LAST == 15,
              "Add an assertion above and fix this one");

tanker_error_t* tanker_future_get_error(tanker_future_t* cfuture)
{
  auto& future = cfuture->future;

  if (!future.has_exception())
    return nullptr;

  if (cfuture->error)
    return cfuture->error.get();

  try
  {
    future.get();
    assert(false && "unreachable code");
    return nullptr;
  }
  catch (Tanker::Errors::Exception const& e)
  {
    cfuture->error.reset(
        new tanker_error_t{static_cast<tanker_error_code_t>(
                               e.errorCode().default_error_condition().value()),
                           duplicateString(e.what())});
  }
  catch (tc::operation_canceled const& e)
  {
    cfuture->error.reset(new tanker_error_t{TANKER_ERROR_OPERATION_CANCELED,
                                            duplicateString(e.what())});
  }
  catch (std::exception const& e)
  {
    cfuture->error.reset(new tanker_error_t{
        TANKER_ERROR_INTERNAL_ERROR,
        duplicateString(
            fmt::format(TFMT("{:s}: {:s}"), typeid(e).name(), e.what()))});
  }
  catch (...)
  {
    cfuture->error.reset(new tanker_error_t{TANKER_ERROR_INTERNAL_ERROR,
                                            duplicateString("unknown error")});
  }
  return cfuture->error.get();
}

bool tanker_future_is_ready(tanker_future_t* future)
{
  return future->future.is_ready();
}

void tanker_future_wait(tanker_future_t* future)
{
  future->future.wait();
}

namespace
{
tanker_future_t* wrapInC(tc::future<void*> fut)
{
  return new tanker_future{tc::future<void*>{std::move(fut)}, nullptr};
}
}

tanker_future_t* tanker_future_then(tanker_future_t* future,
                                    tanker_future_then_t cb,
                                    void* arg)
{
  return makeFuture(future->future.then([cb, arg](auto future) {
    std::unique_ptr<tanker_future_t, void (*)(tanker_future_t*)> fut(
        wrapInC(std::move(future)), [](tanker_future_t* f) { delete f; });
    return cb(fut.get(), arg);
  }));
}

void tanker_future_destroy(tanker_future_t* future)
{
  delete future;
}
