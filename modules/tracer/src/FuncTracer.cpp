#include <Tanker/Tracer/FuncTracer.hpp>

#include "TTracer.hpp"

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Tracer
{
void func_trace(std::string msg, CoroState state, CoroType type)
{
  tracepoint(ttracer, func_beacon, type, state, msg.c_str());
}
}
}
