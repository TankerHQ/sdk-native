#include "MockConnection.hpp"

namespace Tanker
{
MockConnection::MockConnection() : AConnection()
{
  this->connected = [this] { wasConnected(); };
}
}
