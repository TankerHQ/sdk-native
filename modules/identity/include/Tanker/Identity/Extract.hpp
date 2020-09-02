#pragma once

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>

#include <mgs/base64.hpp>
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
    throw Errors::Exception(Errc::InvalidFormat);
  }
  catch (mgs::exceptions::exception const&)
  {
    throw Errors::Exception(Errc::InvalidFormat);
  }
}
}
}
