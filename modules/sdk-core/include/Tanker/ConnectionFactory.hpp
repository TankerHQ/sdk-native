#pragma once

#include <Tanker/AConnection.hpp>
#include <Tanker/SdkInfo.hpp>

#include <optional.hpp>

namespace Tanker
{
struct ConnectionFactory
{
  static ConnectionPtr create(std::string url, nonstd::optional<SdkInfo> info);
};
}
