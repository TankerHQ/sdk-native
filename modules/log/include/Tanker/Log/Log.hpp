#pragma once

#include <Tanker/Config/Config.hpp>
#include <Tanker/Log/LogHandler.hpp>

#include <fmt/core.h>

#include <cstdint>

#define TLOG_CATEGORY(name) \
  static constexpr auto TANKER_LOG_CATEGORY TANKER_MAYBE_UNUSED = #name

namespace Tanker
{
namespace Log
{

template <typename... Args>
void format(Log::Level level,
            char const* cat,
            char const* file,
            std::uint32_t line,
            fmt::string_view format,
            Args const&... args)
{
  auto const message = fmt::vformat(format, {fmt::make_format_args(args...)});
  auto const record = Record{
      cat,
      level,
      file,
      line,
      message.c_str(),
  };
  detail::currentHandler(record);
}
}
}

#define TLOG(LEVEL, ...)                           \
  Tanker::Log::format((Tanker::Log::Level::LEVEL), \
                      (TANKER_LOG_CATEGORY),       \
                      __FILE__,                    \
                      __LINE__,                    \
                      __VA_ARGS__)

#define TDEBUG(...) TLOG(Debug, __VA_ARGS__)

#define TINFO(...) TLOG(Info, __VA_ARGS__)

#define TERROR(...) TLOG(Error, __VA_ARGS__)
