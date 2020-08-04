
#include <Tanker/Log/Log.hpp>
#include <Tanker/Log/LogHandler.hpp>
#include <Tanker/Log/Record.hpp>

namespace Tanker::Log
{
void format(Log::Level level,
            char const* cat,
            char const* file,
            std::uint32_t line,
            fmt::string_view format,
            fmt::format_args args)
{
  auto const message = fmt::vformat(format, args);
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