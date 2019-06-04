#include <ctanker.h>

#include <Tanker/Crypto/InvalidKeySize.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/UserNotFound.hpp>

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

#define CHECK_ENUM(cerror, cpperror)                                 \
  static_assert(static_cast<int>(TANKER_ERROR_##cerror) ==           \
                    static_cast<int>(Tanker::Error::Code::cpperror), \
                "Error code enums not matching")

CHECK_ENUM(NO_ERROR, NoError);
CHECK_ENUM(OTHER, Other);
CHECK_ENUM(INVALID_TANKER_STATUS, InvalidTankerStatus);
CHECK_ENUM(SERVER_ERROR, ServerError);
CHECK_ENUM(RESOURCE_KEY_NOT_FOUND, ResourceKeyNotFound);
CHECK_ENUM(USER_NOT_FOUND, UserNotFound);
CHECK_ENUM(DECRYPT_FAILED, DecryptFailed);
CHECK_ENUM(INVALID_VERIFICATION_KEY, InvalidVerificationKey);
CHECK_ENUM(INTERNAL_ERROR, InternalError);
CHECK_ENUM(INVALID_UNLOCK_PASSWORD, InvalidUnlockPassword);
CHECK_ENUM(INVALID_VERIFICATION_CODE, InvalidVerificationCode);
CHECK_ENUM(VERIFICATION_KEY_ALREADY_EXISTS, VerificationKeyAlreadyExists);
CHECK_ENUM(MAX_VERIFICATION_ATTEMPTS_REACHED, MaxVerificationAttemptsReached);
CHECK_ENUM(INVALID_GROUP_SIZE, InvalidGroupSize);
CHECK_ENUM(RECIPIENT_NOT_FOUND, RecipientNotFound);
CHECK_ENUM(GROUP_NOT_FOUND, GroupNotFound);
CHECK_ENUM(DEVICE_NOT_FOUND, DeviceNotFound);
CHECK_ENUM(IDENTITY_ALREADY_REGISTERED, IdentityAlreadyRegistered);
CHECK_ENUM(OPERATION_CANCELED, OperationCanceled);
CHECK_ENUM(NOTHING_TO_CLAIM, NothingToClaim);
CHECK_ENUM(LAST, Last);

// Hi fellow Tanker developer!
// If you come to this place after being pointed out by your compiler companion
// that the below static_assert failed, it's probably because you forgot to
// update the above assertions. You must add the appropriate CHECK_ENUM()'s.
// Solely then you can fix the static_assert() to allow you and your fellowship
// to continue their journey.
static_assert(TANKER_ERROR_LAST == 21,
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
  catch (Tanker::Crypto::InvalidKeySize const& e)
  {
    throw Tanker::Error::InvalidArgument(e.what());
  }
  catch (cppcodec::parse_error const& e)
  {
    throw Tanker::Error::formatEx<Tanker::Error::InvalidArgument>(
        TFMT("invalid base64: {:s}"), e.what());
  }
  catch (cppcodec::invalid_output_length const& e)
  {
    throw Tanker::Error::formatEx<Tanker::Error::InvalidArgument>(
        TFMT("invalid base64 length: {:s}"), e.what());
  }
  catch (Tanker::Error::Exception const& e)
  {
    cfuture->error.reset(
        new tanker_error_t{static_cast<tanker_error_code_t>(e.code()),
                           duplicateString(e.message())});
  }
  catch (tc::operation_canceled const& e)
  {
    cfuture->error.reset(new tanker_error_t{TANKER_ERROR_OPERATION_CANCELED,
                                            duplicateString(e.what())});
  }
  catch (std::exception const& e)
  {
    cfuture->error.reset(new tanker_error_t{
        TANKER_ERROR_OTHER,
        duplicateString(std::string(typeid(e).name()) + ": " + e.what())});
  }
  catch (...)
  {
    cfuture->error.reset(new tanker_error_t{TANKER_ERROR_OTHER,
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
