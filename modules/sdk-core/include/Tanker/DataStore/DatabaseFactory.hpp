#pragma once

#include <Tanker/DataStore/ADatabase.hpp>

#include <optional>

#include <string>

namespace Tanker
{
namespace DataStore
{
tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    std::optional<Crypto::SymmetricKey> const& userSecret,
    bool exclusive);
}
}
