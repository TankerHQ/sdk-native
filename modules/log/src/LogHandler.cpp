#include <Tanker/Log/LogHandler.hpp>

#include <Tanker/Format/Enum.hpp>

#include <fmt/core.h>

namespace Tanker
{
namespace Log
{
namespace detail
{
LogHandler currentHandler = &consoleHandler;
}

std::string to_string(Level l)
{
  switch (l)
  {
  case Level::Debug:
    return "D";
  case Level::Info:
    return "I";
  case Level::Warning:
    return "W";
  case Level::Error:
    return "E";
  }
  return "Unknown";
}

void consoleHandler(Record const& record)
{
  fmt::print("{0:s}:{1:s}:{2:d}:{3:s}: {4:s}\n",
             record.category,
             record.file,
             record.line,
             record.level,
             record.message);
}

void setLogHandler(LogHandler handler)
{
  if (handler == nullptr)
    detail::currentHandler = &consoleHandler;
  else
    detail::currentHandler = handler;
}
}
}
