#pragma once

#include <functional>

namespace Log
{
using LogHandler =
    std::function<void(char const* category, char level, const char*)>;
void consoleHandler(char const* category, char level, const char*);
void setLogHandler(LogHandler handler);

namespace detail
{
extern LogHandler currentHandler;
}
}
