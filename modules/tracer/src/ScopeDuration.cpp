#include <Tanker/Tracer/ScopeDuration.hpp>

#include "TTracer.hpp"

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Tracer
{
ScopeDuration::ScopeDuration(std::string msg, CoroType type)
  : type(type),
    coro_stack(static_cast<void*>(&tc::get_current_awaiter())),
    msg(std::move(msg)),
    start(std::chrono::high_resolution_clock::now())
{
}

ScopeDuration::~ScopeDuration()
{
  auto const end = std::chrono::high_resolution_clock::now();
  tracepoint(ttracer,
             coro_duration,
             this,
             coro_stack,
             type,
             std::chrono::duration_cast<std::chrono::duration<float, std::milli>>(end - start).count(),
             msg.c_str());
}
}
}
