#pragma once

#include <Tanker/Config/Config.hpp>
#include <Tanker/Errors/Errc.hpp>

#include <fmt/format.h>

#include <exception>
#include <string>
#include <system_error>
#include <type_traits>

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

private:
  std::error_code _errorCode;
  std::string _message;

  static std::string formatError(std::error_code ec,
                                 std::string const& message);
};

TANKER_WARN_UNUSED_RESULT Exception formatEx(std::error_code ec,
                                             fmt::string_view format,
                                             fmt::format_args args);

template <typename Code, typename... Args>
TANKER_WARN_UNUSED_RESULT auto formatEx(Code c,
                                        fmt::string_view format,
                                        Args const&... args)
    -> std::enable_if_t<std::is_error_code_enum<Code>::value, Exception>
{
  return formatEx(
      static_cast<std::error_code>(c), format, fmt::make_format_args(args...));
}

template <typename... Args>
TANKER_WARN_UNUSED_RESULT Exception formatEx(Errc c,
                                             fmt::string_view format,
                                             Args const&... args)
{
  return formatEx(make_error_code(c), format, fmt::make_format_args(args...));
}
}
}
