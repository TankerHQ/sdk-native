#include <ctanker/stream.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Streams/StreamEncryptor.hpp>
#include <Tanker/Types/SResourceId.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include "Stream.hpp"
#include <ctanker/private/Utils.hpp>

#include <ctanker/async/private/CFuture.hpp>

using namespace Tanker;
using namespace Tanker::Errors;

namespace
{
auto wrapCallback(tanker_stream_input_source_t cb, void* additional_data)
{
  return [=](std::uint8_t* out, std::int64_t n) -> tc::cotask<std::int64_t> {
    tc::promise<std::int64_t> p;
    // do not forget to take the promise by ref, the lambda will be deleted as
    // soon as it has run.
    // We are in a coroutine, capturing a stack variable is ok, because we await
    // until the operation finishes.
    // Use tc::async so that the C callback is not run in a coroutine to avoid
    // issues with Android.
    tc::async([=, &p]() mutable {
      cb(out,
         n,
         reinterpret_cast<tanker_stream_read_operation_t*>(&p),
         additional_data);
    });
    TC_RETURN(TC_AWAIT(p.get_future()));
  };
}
}

void tanker_stream_read_operation_finish(tanker_stream_read_operation_t* op,
                                         int64_t nb_read)
{
  auto p = reinterpret_cast<tc::promise<std::int64_t>*>(op);
  if (nb_read == -1)
  {
    p->set_exception(std::make_exception_ptr(
        Exception(make_error_code(Errc::IOError), "failed to read input")));
  }
  else
    p->set_value(nb_read);
}

tanker_future_t* tanker_stream_encrypt(tanker_t* session,
                                       tanker_stream_input_source_t cb,
                                       void* additional_data,
                                       tanker_encrypt_options_t const* options)
{
  std::vector<SPublicIdentity> spublicIdentities{};
  std::vector<SGroupId> sgroupIds{};

  if (options)
  {
    if (options->version != 2)
    {
      return makeFuture(tc::make_exceptional_future<void>(
          formatEx(Errc::InvalidArgument,
                   "unsupported tanker_encrypt_options struct version")));
    }
    spublicIdentities =
        to_vector<SPublicIdentity>(options->recipient_public_identities,
                                   options->nb_recipient_public_identities);
    sgroupIds = to_vector<SGroupId>(options->recipient_gids,
                                    options->nb_recipient_gids);
  }

  auto tanker = reinterpret_cast<AsyncCore*>(session);
  return makeFuture(
      tanker
          ->makeStreamEncryptor(
              wrapCallback(cb, additional_data), spublicIdentities, sgroupIds)
          .and_then(
              tc::get_synchronous_executor(),
              [](Streams::StreamEncryptor encryptor) {
                auto c_stream = new tanker_stream;
                c_stream->resourceId = SResourceId{
                    cppcodec::base64_rfc4648::encode(encryptor.resourceId())};
                c_stream->inputSource = std::move(encryptor);
                return static_cast<void*>(c_stream);
              }));
}

tanker_future_t* tanker_stream_decrypt(tanker_t* session,
                                       tanker_stream_input_source_t cb,
                                       void* data)
{
  auto tanker = reinterpret_cast<AsyncCore*>(session);
  return makeFuture(tanker->makeStreamDecryptor(wrapCallback(cb, data))
                        .and_then(tc::get_synchronous_executor(),
                                  [](GenericStreamDecryptor decryptor) {
                                    auto c_stream = new tanker_stream;
                                    c_stream->resourceId = SResourceId{
                                        cppcodec::base64_rfc4648::encode(
                                            decryptor.resourceId())};
                                    c_stream->inputSource =
                                        std::move(decryptor);
                                    return static_cast<void*>(c_stream);
                                  }));
}

tanker_future_t* tanker_stream_read(tanker_stream_t* stream,
                                    uint8_t* buffer,
                                    int64_t buffer_size)
{
  return makeFuture(stream->canceler.run([&]() mutable {
    return tc::async_resumable([=]() -> tc::cotask<void*> {
      TC_RETURN(reinterpret_cast<void*>(
          TC_AWAIT(stream->inputSource(buffer, buffer_size))));
    });
  }));
}

tanker_expected_t* tanker_stream_get_resource_id(tanker_stream_t* stream)
{
  return makeFuture(tc::make_ready_future(
      static_cast<void*>(duplicateString(stream->resourceId.string()))));
}

tanker_future_t* tanker_stream_close(tanker_stream_t* stream)
{
  return makeFuture(tc::async([=] { delete stream; }));
}
