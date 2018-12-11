#include <Tanker/ConnectionFactory.hpp>

#include <Tanker/Connection.hpp>

namespace Tanker
{
ConnectionPtr ConnectionFactory::create(std::string url,
                                        nonstd::optional<SdkInfo> info)
{
  return std::make_unique<Connection>(std::move(url), std::move(info));
}
}
