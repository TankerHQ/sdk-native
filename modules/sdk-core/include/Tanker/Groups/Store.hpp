#pragma once

#include <Tanker/Groups/Group.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <optional>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::DataStore
{
class Database;
}

namespace Tanker::Groups
{
class Store
{
public:
  Store(Store const&) = delete;
  Store(Store&&) = delete;
  Store& operator=(Store const&) = delete;
  Store& operator=(Store&&) = delete;

  Store(DataStore::Database* dbConn);

private:
  DataStore::Database* _db;
};
}
