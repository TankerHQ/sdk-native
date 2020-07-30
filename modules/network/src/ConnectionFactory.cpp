#include <Tanker/Network/ConnectionFactory.hpp>

#include <Tanker/Network/Connection.hpp>

namespace Tanker
{
namespace Network
{
ConnectionPtr ConnectionFactory::create(std::string url, SdkInfo info)
{
  return std::make_unique<Connection>(std::move(url), std::move(info));
}

ConnectionPtr ConnectionFactory::create(std::string url, std::string context)
{
  return std::make_unique<Connection>(std::move(url), std::move(context));
}
}
}
