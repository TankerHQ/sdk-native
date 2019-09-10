#include <ctanker/filekit.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/StreamEncryptor.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <tconcurrent/async.hpp>

#include <ctanker/async/private/CFuture.hpp>

#include "Stream.hpp"
#include <ctanker/private/Utils.hpp>

using namespace Tanker::Errors;
using Tanker::AsyncCore;

namespace
{
auto convertMetadata(tanker_metadata_t* meta)
{
  Tanker::FileKit::Metadata m{};
  if (meta)
  {
    if (meta->version != 1)
      throw formatEx(Errc::InvalidArgument,
                     "unsupported tanker_metadata_t struct version");
    if (meta->last_modified != 0)
      m.lastModified = std::chrono::milliseconds{meta->last_modified};
    if (meta->mime)
      m.mime = std::string(meta->mime);
    if (meta->name)
      m.name = std::string(meta->name);
  }
  return m;
}

auto convertMetadata(Tanker::FileKit::Metadata m)
{
  using namespace std::chrono_literals;
  auto meta = new tanker_metadata_t{1, nullptr, nullptr, 0};
  if (m.name.has_value())
    meta->name = duplicateString(m.name.value());
  if (m.mime.has_value())
    meta->mime = duplicateString(m.mime.value());
  meta->last_modified = m.lastModified.value_or(0ms).count();
  return meta;
}

auto convertUploadOption(tanker_upload_options_t* options)
{
  std::vector<Tanker::SPublicIdentity> spublicIdentities{};
  std::vector<Tanker::SGroupId> sgroupIds{};
  if (options)
  {
    if (options->version != 1)
      throw formatEx(Errc::InvalidArgument,
                     "unsupported tanker_upload_options_t struct verison");
    spublicIdentities = to_vector<Tanker::SPublicIdentity>(
        options->recipient_public_identities,
        options->nb_recipient_public_identities);
    sgroupIds = to_vector<Tanker::SGroupId>(options->recipient_gids,
                                            options->nb_recipient_gids);
  }
  return std::make_tuple(spublicIdentities, sgroupIds);
}

void tanker_metadata_destroy(tanker_metadata_t* metadata)
{
  if (metadata->version != 1)
    throw formatEx(Errc::InvalidArgument,
                   "unsupported tanker_metadata_t struct version");
  std::free((char*)metadata->mime);
  std::free((char*)metadata->name);
  delete metadata;
}

auto wrapCallback(tanker_stream_input_source_t cb, void* additional_data)
{
  return [=](std::uint8_t* out, std::int64_t n) -> tc::cotask<std::int64_t> {
    tc::promise<std::int64_t> p;
    // do not forget to take the promise by ref, the lambda will be deleted as
    // soon as it has run.
    // We are in a coroutine, capturing a stack variable is ok, because we
    // await until the operation finishes. Use tc::async so that the C
    // callback is not run in a coroutine to avoid issues with Android.
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

tanker_future_t* tanker_upload(tanker_t* ctanker,
                               uint8_t const* data,
                               uint64_t data_size,
                               tanker_metadata_t* metadata,
                               tanker_upload_options_t* options) try
{
  auto core = reinterpret_cast<AsyncCore*>(ctanker);
  auto const o = convertUploadOption(options);
  auto const m = convertMetadata(metadata);
  return makeFuture(tc::async_resumable([=]() -> tc::cotask<void*> {
    auto fileId =
        TC_AWAIT(core->upload(gsl::make_span(data, data_size),
                              m,
                              std::get<std::vector<Tanker::SPublicIdentity>>(o),
                              std::get<std::vector<Tanker::SGroupId>>(o)));
    TC_RETURN(static_cast<void*>(duplicateString(
        cppcodec::base64_rfc4648::encode<Tanker::SResourceId>(fileId)
            .string())));
  }));
}
catch (...)
{
  tc::promise<void> p;
  p.set_exception(std::current_exception());
  return makeFuture(p.get_future());
}

tanker_future_t* tanker_upload_stream(tanker_t* ctanker,
                                      tanker_stream_input_source_t source,
                                      uint64_t data_size,
                                      tanker_metadata_t* metadata,
                                      tanker_upload_options_t* options) try
{
  auto core = reinterpret_cast<AsyncCore*>(ctanker);
  auto const o = convertUploadOption(options);
  auto const m = convertMetadata(metadata);
  return makeFuture(tc::async_resumable([=]() -> tc::cotask<void*> {
    auto fileId = TC_AWAIT(
        core->uploadStream(wrapCallback(source, nullptr),
                           data_size,
                           m,
                           std::get<std::vector<Tanker::SPublicIdentity>>(o),
                           std::get<std::vector<Tanker::SGroupId>>(o)));
    TC_RETURN(static_cast<void*>(duplicateString(
        cppcodec::base64_rfc4648::encode<Tanker::SResourceId>(fileId)
            .string())));
  }));
}
catch (...)
{
  tc::promise<void> p;
  p.set_exception(std::current_exception());
  return makeFuture(p.get_future());
}

tanker_future_t* tanker_download(tanker_t* ctanker, char const* resource_id)
{
  auto core = reinterpret_cast<AsyncCore*>(ctanker);

  return makeFuture(tc::async_resumable(
      [=,
       resourceId = Tanker::SResourceId{resource_id}]() -> tc::cotask<void*> {
        auto res = TC_AWAIT(core->download(resourceId));
        auto download_result = new tanker_download_result_t;
        download_result->data = new uint8_t[res.data.size()];
        std::copy(res.data.begin(), res.data.end(), download_result->data);
        download_result->metadata = convertMetadata(res.metadata);
        TC_RETURN(download_result);
      }));
}

tanker_future_t* tanker_download_stream(tanker_t* ctanker,
                                        char const* resource_id)
{
  auto core = reinterpret_cast<AsyncCore*>(ctanker);

  return makeFuture(tc::async_resumable(
      [=,
       resourceId = Tanker::SResourceId{resource_id}]() -> tc::cotask<void*> {
        auto res = TC_AWAIT(core->downloadStream(resourceId));
        auto c_stream = new tanker_stream_t;
        c_stream->resourceId = resourceId;
        c_stream->inputSource = std::move(res.stream);
        auto download_result = new tanker_download_stream_result_t{
            c_stream, convertMetadata(res.metadata)};
        TC_RETURN(download_result);
      }));
}

tanker_future_t* tanker_download_result_destroy(
    tanker_download_result_t* download_result)
{
  return makeFuture(tc::async([=] {
    delete[] download_result->data;
    tanker_metadata_destroy(download_result->metadata);
    delete download_result;
  }));
}

tanker_future_t* tanker_download_stream_result_destroy(
    tanker_download_stream_result_t* download_result)
{
  return makeFuture(tc::async([=] {
    delete download_result->stream;
    tanker_metadata_destroy(download_result->metadata);
    delete download_result;
  }));
}
