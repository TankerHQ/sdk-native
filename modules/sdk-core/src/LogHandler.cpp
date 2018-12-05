#include <Tanker/LogHandler.hpp>

#include <cstdio>

namespace Log
{
namespace detail
{
LogHandler currentHandler = &consoleHandler;
}

void consoleHandler(char const*, char, char const* msg)
{
  std::fputs(msg, stdout);
}

void setLogHandler(LogHandler handler)
{
  if (handler == nullptr)
    detail::currentHandler = &consoleHandler;
  else
    detail::currentHandler = handler;
}
}
