#pragma once

#include <Tanker/DataStore/ADatabase.hpp>

#include <optional.hpp>

#include <string>

namespace Tanker
{
namespace DataStore
{
tc::cotask<DatabasePtr> createDatabase(
    std::string const& dbPath,
    nonstd::optional<Crypto::SymmetricKey> const& userSecret,
    bool exclusive);
};
}
