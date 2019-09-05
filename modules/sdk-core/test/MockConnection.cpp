#include "MockConnection.hpp"

namespace Tanker
{
MockConnection::MockConnection() : Network::AConnection()
{
  this->connected = [this] { wasConnected(); };
}
}
