#pragma once

#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <optional.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Crypto
{
class Mac;
}

struct Entry;

namespace DataStore
{
class Database;
}

class Trustchain
{
public:
  Trustchain(DataStore::Database* dbConn);
  Trustchain(Trustchain const&) = delete;
  Trustchain(Trustchain&&) = delete;
  Trustchain& operator=(Trustchain const&) = delete;
  Trustchain& operator=(Trustchain&&) = delete;

  tc::cotask<void> addEntry(Entry const& entry);

  tc::cotask<nonstd::optional<Entry>> findKeyPublish(
      Crypto::Mac const& resourceId) const;

  tc::cotask<uint64_t> getLastIndex();

private:
  DataStore::Database* _db;

  uint64_t _lastIndex = 0;
};
}
