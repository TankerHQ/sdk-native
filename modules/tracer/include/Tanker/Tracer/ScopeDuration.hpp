#pragma once

#ifdef TANKER_ENABLE_TRACER
#include <Tanker/Tracer/CoroStatus.hpp>

#include <chrono>
#include <string>

namespace Tanker
{
namespace Tracer
{
struct ScopeDuration
{
  ScopeDuration(std::string msg, CoroType type = CoroType::Proc);
  ~ScopeDuration();

private:
  CoroType type;
  void* coro_stack;
  std::string msg;
  std::chrono::high_resolution_clock::time_point start;
};
}
}

#define SCOPE_DURATION_(TEXT, COROTYPE)           \
  ::Tanker::Tracer::ScopeDuration scope_duration_ \
  {                                               \
    (TEXT), (COROTYPE)                            \
  }
#else
#define SCOPE_DURATION_(TEXT, COROTYPE)
#endif

#define SCOPE_DURATION_T(TEXT, COROTYPE) SCOPE_DURATION_(TEXT, ::Tanker::Tracer::COROTYPE)

#define FUNC_DURATION(COROTYPE) SCOPE_DURATION_(__func__, ::Tanker::Tracer::COROTYPE)
