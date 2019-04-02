#pragma once

#include <Tanker/EnumTrait.hpp>

#include <functional>
#include <string>

namespace Tanker
{
namespace Log
{
enum class Level : std::uint8_t
{
  Debug = 1,
  Info,
  Warning,
  Error,
};

std::string to_string(Level l);

struct Record
{
  char const* category;
  Level level;
  char const* file;
  std::uint32_t line;
  char const* message;
};

using LogHandler = std::function<void(Record const&)>;
void consoleHandler(Record const&);
void setLogHandler(LogHandler handler);

namespace detail
{
extern LogHandler currentHandler;
}
}

template <>
struct is_enum_type<Log::Level> : std::true_type
{
};
}
