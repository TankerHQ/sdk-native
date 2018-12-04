#include <Tanker/DataStore/ADatabase.hpp>

#include <Tanker/DataStore/Database.hpp>

namespace Tanker
{
namespace DataStore
{
tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    nonstd::optional<Crypto::SymmetricKey> const& userSecret,
    bool exclusive)
{
  TC_RETURN(std::make_unique<Database>(dbPath, userSecret, exclusive));
}
}
}
