#pragma once

#include <Tanker/Config/Config.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <fmt/format.h>

#include <exception>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace Tanker
{
namespace Errors
{
class Exception : public std::exception
{
public:
  Exception() = delete;
  explicit Exception(std::error_code ec);
  Exception(std::error_code ec, std::string const& message);

  char const* what() const noexcept override;
  std::error_code const& errorCode() const;
  std::string const& backtrace() const;

private:
  std::error_code _errorCode;
  std::string _backtrace;
  std::string _message;

  static std::string formatError(std::error_code ec,
                                 std::string const& message);
  static std::string backtraceAsString();
};

template <typename Code, typename... Args>
TANKER_WARN_UNUSED_RESULT auto formatEx(Code c,
                                        fmt::string_view format,
                                        Args const&... args)
    -> std::enable_if_t<std::is_error_code_enum<Code>::value, Exception>
{
  return Exception(c, fmt::vformat(format, {fmt::make_format_args(args...)}));
}

template <typename... Args>
TANKER_WARN_UNUSED_RESULT Exception formatEx(Errc c,
                                             fmt::string_view format,
                                             Args const&... args)
{
  return Exception(make_error_code(c),
                   fmt::vformat(format, {fmt::make_format_args(args...)}));
}
}
}
