#pragma once

#include <Tanker/Log/Level.hpp>
#include <Tanker/Log/Record.hpp>

#include <functional>
#include <string>

namespace Tanker
{
namespace Log
{
std::string to_string(Level l);

using LogHandler = std::function<void(Record const&)>;
void consoleHandler(Record const&);
void setLogHandler(LogHandler handler);

namespace detail
{
extern LogHandler currentHandler;
}
}
}
