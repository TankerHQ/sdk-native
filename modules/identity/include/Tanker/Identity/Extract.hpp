#pragma once

#include <Tanker/Identity/UserToken.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
nlohmann::json extract(std::string const& token);

template <typename I>
I extract(std::string const& token)
{
  return extract(token).get<I>();
}
}
}
