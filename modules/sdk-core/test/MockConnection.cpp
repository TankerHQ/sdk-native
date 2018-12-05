#include "MockConnection.hpp"

namespace Tanker
{
MockConnection::MockConnection() : AConnection()
{
  this->connected.connect([this] { wasConnected(); });
}
}
