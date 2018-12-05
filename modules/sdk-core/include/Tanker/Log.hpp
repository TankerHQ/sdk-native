#pragma once
#include <fmt/core.h>

#include <Tanker/LogHandler.hpp>

#ifdef __GNUC__
#define TANKER_MAYBE_UNUSED __attribute__((unused))
#else
#define TANKER_MAYBE_UNUSED
#endif

#define TLOG_CATEGORY(name) \
  static constexpr auto TANKER_LOG_CATEGORY TANKER_MAYBE_UNUSED = #name

namespace Log
{

enum class Level : char
{
  Debug = 'D',
  Info = 'I',
  Error = 'E',
};

inline std::string format_imp(fmt::format_args args)
{
  return fmt::vformat("{0:s}:{1:s}:{2:d}:{3:c}: {4:s}\n", args);
}

template <typename... Args>
void format(Log::Level level,
            char const* cat,
            char const* file,
            int line,
            char const* format,
            Args const&... args)
{
  auto const s = format_imp(fmt::make_format_args(
      cat,
      file,
      line,
      static_cast<char>(level),
      fmt::vformat(format, fmt::make_format_args(args...))));
  detail::currentHandler(cat, static_cast<char>(level), s.c_str());
}
}

#define TLOG(LEVEL, ...) \
  Log::format(           \
      Log::Level::LEVEL, TANKER_LOG_CATEGORY, __FILE__, __LINE__, __VA_ARGS__)

#define TDEBUG(...) TLOG(Debug, __VA_ARGS__)

#define TINFO(...) TLOG(Info, __VA_ARGS__)

#define TERROR(...) TLOG(Error, __VA_ARGS__)
