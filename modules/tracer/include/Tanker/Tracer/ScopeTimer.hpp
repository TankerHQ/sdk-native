#pragma once

#ifdef TANKER_ENABLE_TRACER
#include <Tanker/Tracer/CoroStatus.hpp>
#include <string>

namespace Tanker
{
namespace Tracer
{

struct ScopeTimer
{
  ScopeTimer(std::string, CoroType type = CoroType::Proc);
  void progress(char const*);
  ~ScopeTimer();

private:
  CoroType type;
  void* coro_stack;
  std::string msg;
};
}
}

#define SCOPE_TIMER_(TEXT, COROTYPE)        \
  ::Tanker::Tracer::ScopeTimer scope_timer_ \
  {                                         \
    (TEXT), (COROTYPE)                      \
  }

#else
#define SCOPE_TIMER_(TEXT, COROTYPE)
#endif

#define SCOPE_TIMER(TEXT, COROTYPE) SCOPE_TIMER_(TEXT, ::Tanker::Tracer::COROTYPE)

#define FUNC_TIMER(COROTYPE) SCOPE_TIMER_(__func__, ::Tanker::Tracer::COROTYPE)
