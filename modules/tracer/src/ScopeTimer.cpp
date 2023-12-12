#include <Tanker/Tracer/ScopeTimer.hpp>

#include "TTracer.hpp"

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Tracer
{
ScopeTimer::ScopeTimer(std::string msg, CoroType type)
  : type(type), coro_stack(static_cast<void*>(&tc::get_current_awaiter())), msg(std::move(msg))
{
  tracepoint(ttracer, coro_beacon, this, coro_stack, type, CoroState::Begin, this->msg.c_str());
}

void ScopeTimer::progress(const char* msg)
{
  tracepoint(
      ttracer, coro_beacon, this, static_cast<void*>(&tc::get_current_awaiter()), type, CoroState::Progress, msg);
}

ScopeTimer::~ScopeTimer()
{
  tracepoint(ttracer, coro_beacon, this, coro_stack, type, CoroState::End, this->msg.c_str());
}
}
}
