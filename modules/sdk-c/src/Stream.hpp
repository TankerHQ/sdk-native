#pragma once

#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Types/SResourceId.hpp>

#include <tconcurrent/task_canceler.hpp>

inline auto wrapCallback(tanker_stream_input_source_t cb, void* additional_data)
{
  return [=](std::uint8_t* out, std::int64_t n) -> tc::cotask<std::int64_t> {
    tc::promise<std::int64_t> p;
    // Do not forget to take the promise by ref, the lambda will be deleted as
    // soon as it has run.
    // We are in a coroutine, capturing a stack variable is ok, because we await
    // until the operation finishes.
    tc::dispatch_on_thread_context([=, &p]() mutable {
      cb(out,
         n,
         reinterpret_cast<tanker_stream_read_operation_t*>(&p),
         additional_data);
    });
    TC_RETURN(TC_AWAIT(p.get_future()));
  };
}

struct tanker_stream
{
  Tanker::Streams::InputSource inputSource;
  Tanker::SResourceId resourceId;
  tc::task_canceler canceler;
};
