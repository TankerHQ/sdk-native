#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ttracer

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ttracer.h"

#if !defined(TTRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define TTRACE_H

#include <Tanker/Tracer/CoroStatus.hpp>

#include <lttng/tracepoint.h>

TRACEPOINT_ENUM(ttracer,
                coro_state,
                TP_ENUM_VALUES(ctf_enum_value("Begin", Tanker::Tracer::CoroState::Begin)
                                   ctf_enum_value("Progress", Tanker::Tracer::CoroState::Progress)
                                       ctf_enum_value("End", Tanker::Tracer::CoroState::End)
                                           ctf_enum_value("Error", Tanker::Tracer::CoroState::Error)))

TRACEPOINT_ENUM(ttracer,
                coro_type,
                TP_ENUM_VALUES(ctf_enum_value("Proc", Tanker::Tracer::CoroType::Proc)
                                   ctf_enum_value("Net", Tanker::Tracer::CoroType::Net)
                                       ctf_enum_value("DB", Tanker::Tracer::CoroType::DB)))

TRACEPOINT_EVENT(ttracer,
                 coro_beacon,
                 TP_ARGS(void*,
                         id,
                         void*,
                         pstack,
                         Tanker::Tracer::CoroType,
                         ptype,
                         Tanker::Tracer::CoroState,
                         pstate,
                         const char*,
                         cmsg),
                 TP_FIELDS(ctf_enum(ttracer, coro_state, int, state, pstate) ctf_integer_hex(void*, coro_id, id)
                               ctf_integer_hex(void*, coro_stack, pstack) ctf_enum(ttracer, coro_type, int, type, ptype)
                                   ctf_string(msg, cmsg)))

TRACEPOINT_EVENT(
    ttracer,
    coro_duration,
    TP_ARGS(void*, id, void*, pstack, Tanker::Tracer::CoroType, ptype, double, duration, char const*, cmsg),
    TP_FIELDS(ctf_integer_hex(void*, coro_id, id) ctf_integer_hex(void*, coro_stack, pstack)
                  ctf_float(double, coro_ts, duration) ctf_enum(ttracer, coro_type, int, type, ptype)
                      ctf_string(msg, cmsg)))
TRACEPOINT_EVENT(ttracer,
                 func_beacon,
                 TP_ARGS(Tanker::Tracer::CoroType, ptype, Tanker::Tracer::CoroState, pstate, char const*, cmsg),
                 TP_FIELDS(ctf_enum(ttracer, coro_state, int, state, pstate)
                               ctf_enum(ttracer, coro_type, int, type, ptype) ctf_string(msg, cmsg)))

#endif /* TTRACE_H */

#include <lttng/tracepoint-event.h>
