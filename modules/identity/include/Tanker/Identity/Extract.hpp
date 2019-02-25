#pragma once

#include <Tanker/Identity/UserToken.hpp>

#include <Tanker/Crypto/base64.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
template <typename I>
I extract(std::string const& token)
{
  return nlohmann::json::parse(base64::decode(token)).get<I>();
}
}
}
