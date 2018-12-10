#include <Tanker/ConnectionFactory.hpp>

#include <Tanker/Connection.hpp>

namespace Tanker
{
ConnectionPtr ConnectionFactory::create(std::string url)
{
  return std::make_unique<Connection>(std::move(url));
}
}
