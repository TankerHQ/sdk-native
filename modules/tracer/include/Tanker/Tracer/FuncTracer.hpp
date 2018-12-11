#pragma once

#ifdef TANKER_ENABLE_TRACER
#include <Tanker/Tracer/CoroStatus.hpp>
#include <string>

namespace Tanker
{
namespace Tracer
{
void func_trace(std::string msg,
                CoroState state,
                CoroType type = CoroType::Proc);
}
}

#define FUNC_TRACE_(TEXT, STATE, COROTYPE) \
  ::Tanker::Tracer::func_trace(            \
      (TEXT), (::Tanker::Tracer::STATE), (::Tanker::Tracer::COROTYPE))
#else
#define FUNC_TRACE_(TEXT, STATE, COROTYPE)
#endif

#define FUNC_BEGIN(TEXT, COROTYPE) FUNC_TRACE_(TEXT, Begin, COROTYPE)
#define FUNC_END(TEXT, COROTYPE) FUNC_TRACE_(TEXT, End, COROTYPE)
