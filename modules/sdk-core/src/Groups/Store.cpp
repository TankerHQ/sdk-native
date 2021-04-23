#include <Tanker/Groups/Store.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/Database.hpp>
#include <Tanker/DataStore/Utils.hpp>
#include <Tanker/DbModels/Groups.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <sqlpp11/sqlite3/insert_or.h>

#include <optional>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY(GroupStore);

using Tanker::Trustchain::GroupId;

namespace Tanker::Groups
{


Store::Store(DataStore::Database* dbConn) : _db(dbConn)
{
}

}