#pragma once

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
namespace detail
{
nlohmann::json extract(std::string const& token);
}

template <typename I>
I extract(std::string const& token)
{
  try
  {
    return detail::extract(token).get<I>();
  }
  catch (nlohmann::json::exception const&)
  {
    throw Errors::formatEx(Errc::InvalidFormat, "json deserialization failed");
  }
  catch (cppcodec::parse_error const&)
  {
    throw Errors::formatEx(Errc::InvalidFormat,
                           "base64 deserialization failed");
  }
}
}
}
