#include <ctanker/stream.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Types/SResourceId.hpp>

#include <mgs/base64.hpp>

#include "CPadding.hpp"
#include "Stream.hpp"
#include <ctanker/private/Utils.hpp>

#include <ctanker/async/private/CFuture.hpp>

using namespace Tanker;
using namespace Tanker::Errors;

void tanker_stream_read_operation_finish(tanker_stream_read_operation_t* op, int64_t nb_read)
{
  auto p = reinterpret_cast<tc::promise<std::int64_t>*>(op);
  if (nb_read == -1)
  {
    p->set_exception(std::make_exception_ptr(Exception(make_error_code(Errc::IOError), "failed to read input")));
  }
  else
    p->set_value(nb_read);
}

tanker_future_t* tanker_stream_encrypt(tanker_t* session,
                                       tanker_stream_input_source_t cb,
                                       void* additional_data,
                                       tanker_encrypt_options_t const* options)
{
  return makeFuture(tc::sync([&] {
                      std::vector<SPublicIdentity> spublicIdentities{};
                      std::vector<SGroupId> sgroupIds{};
                      bool shareWithSelf = true;
                      std::optional<uint32_t> paddingStepOpt;

                      if (options)
                      {
                        if (options->version != 4)
                        {
                          throw formatEx(Errc::InvalidArgument, "unsupported tanker_encrypt_options struct version");
                        }
                        spublicIdentities = to_vector<SPublicIdentity>(
                            options->share_with_users, options->nb_users, "share_with_users");
                        sgroupIds =
                            to_vector<SGroupId>(options->share_with_groups, options->nb_groups, "share_with_groups");
                        shareWithSelf = options->share_with_self;

                        paddingStepOpt = cPaddingToOptPadding(options->padding_step);
                      }

                      auto tanker = reinterpret_cast<AsyncCore*>(session);
                      return tanker->makeEncryptionStream(wrapCallback(cb, additional_data),
                                                          spublicIdentities,
                                                          sgroupIds,
                                                          Core::ShareWithSelf{shareWithSelf},
                                                          paddingStepOpt);
                    })
                        .unwrap()
                        .and_then(tc::get_synchronous_executor(), [](auto encryptor) {
                          auto c_stream = new tanker_stream;
                          c_stream->resourceId = SResourceId{mgs::base64::encode(std::get<1>(encryptor))};
                          c_stream->inputSource = std::move(std::get<0>(encryptor));
                          return static_cast<void*>(c_stream);
                        }));
}

tanker_future_t* tanker_stream_decrypt(tanker_t* session, tanker_stream_input_source_t cb, void* data)
{
  auto tanker = reinterpret_cast<AsyncCore*>(session);
  return makeFuture(
      tanker->makeDecryptionStream(wrapCallback(cb, data)).and_then(tc::get_synchronous_executor(), [](auto decryptor) {
        auto c_stream = new tanker_stream;
        c_stream->resourceId = SResourceId{mgs::base64::encode(std::get<1>(decryptor))};
        c_stream->inputSource = std::move(std::get<0>(decryptor));
        return static_cast<void*>(c_stream);
      }));
}

tanker_future_t* tanker_stream_read(tanker_stream_t* stream, uint8_t* buffer, int64_t buffer_size)
{
  return makeFuture(stream->canceler.run([&]() mutable {
    return tc::async_resumable([=]() -> tc::cotask<void*> {
      TC_RETURN(reinterpret_cast<void*>(TC_AWAIT(stream->inputSource(gsl::make_span(buffer, buffer_size)))));
    });
  }));
}

tanker_expected_t* tanker_stream_get_resource_id(tanker_stream_t* stream)
{
  return makeFuture(tc::make_ready_future(static_cast<void*>(duplicateString(stream->resourceId.string()))));
}

tanker_future_t* tanker_stream_close(tanker_stream_t* stream)
{
  return makeFuture(tc::async([=] { delete stream; }));
}
