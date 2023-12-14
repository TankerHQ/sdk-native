#pragma once

#include <Tanker/Config/Config.hpp>
#include <Tanker/Log/Level.hpp>

#include <fmt/core.h>

#include <cstdint>

#define TLOG_CATEGORY(name) static constexpr auto TANKER_LOG_CATEGORY TANKER_MAYBE_UNUSED = #name

namespace Tanker::Log
{
void format(Log::Level level,
            char const* cat,
            char const* file,
            std::uint32_t line,
            fmt::string_view format,
            fmt::format_args args);

namespace detail
{
template <typename... Args>
void format(Log::Level level,
            char const* cat,
            char const* file,
            std::uint32_t line,
            fmt::string_view format,
            Args const&... args)
{
  Tanker::Log::format(level, cat, file, line, format, fmt::make_format_args(args...));
}
}
}

#define TLOG(LEVEL, ...) \
  Tanker::Log::detail::format((Tanker::Log::Level::LEVEL), (TANKER_LOG_CATEGORY), __FILE__, __LINE__, __VA_ARGS__)

#define TDEBUG(...) TLOG(Debug, __VA_ARGS__)

#define TINFO(...) TLOG(Info, __VA_ARGS__)

#define TWARNING(...) TLOG(Warning, __VA_ARGS__)

#define TERROR(...) TLOG(Error, __VA_ARGS__)
