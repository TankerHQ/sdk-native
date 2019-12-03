#pragma once

#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Network/SdkInfo.hpp>

#include <optional>

namespace Tanker
{
namespace Network
{
struct ConnectionFactory
{
  static ConnectionPtr create(std::string url, std::optional<SdkInfo> info);
};
}
}
