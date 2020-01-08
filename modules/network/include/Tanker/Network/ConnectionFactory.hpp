#pragma once

#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Network/SdkInfo.hpp>

namespace Tanker
{
namespace Network
{
struct ConnectionFactory
{
  static ConnectionPtr create(std::string url, SdkInfo info);
  static ConnectionPtr create(std::string url, std::string context);
};
}
}
