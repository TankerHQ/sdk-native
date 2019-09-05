#pragma once

#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Network/SdkInfo.hpp>

#include <optional.hpp>

namespace Tanker
{
namespace Network
{
struct ConnectionFactory
{
  static ConnectionPtr create(std::string url, nonstd::optional<SdkInfo> info);
};
}
}
