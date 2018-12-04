#include <Tanker/AConnection.hpp>

#include <Tanker/Connection.hpp>

namespace Tanker
{
ConnectionPtr makeConnection(std::string const& url)
{
  return std::make_unique<Connection>(url);
}
}
